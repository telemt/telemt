use std::sync::Arc;
use std::time::Duration;

use rand::RngExt;
use tracing::warn;

use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use crate::startup::{COMPONENT_TLS_FRONT_BOOTSTRAP, StartupTracker};
use crate::tls_front::TlsFrontCache;
use crate::tls_front::cache::TlsFullCertBudget;
use crate::tls_front::fetcher::TlsFetchStrategy;
use crate::transport::UpstreamManager;

use super::generation::RuntimeTaskScope;

/// First retry delay for domains that are still served from the default profile.
const TLS_FRONT_RETRY_INITIAL: Duration = Duration::from_secs(30);
/// Retry delay cap; far below the regular refresh period.
const TLS_FRONT_RETRY_MAX: Duration = Duration::from_secs(600);

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
    async fn fetch_domains(&self, domains: &[String], failure_message: &'static str) {
        let mut join = tokio::task::JoinSet::new();
        for domain in domains {
            let domain = domain.clone();
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
        self.fetch_with_budget(&self.domains, phase).await;
    }

    async fn fetch_with_budget(&self, domains: &[String], phase: &'static str) {
        if tokio::time::timeout(
            self.strategy.total_budget,
            self.fetch_domains(domains, phase),
        )
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

/// Regular refresh period for fetched profiles: 4-6h base plus up to 2h jitter.
fn regular_refresh_delay() -> Duration {
    let base_secs = rand::rng().random_range(4 * 3600..=6 * 3600);
    let jitter_secs = rand::rng().random_range(0..=7200);
    Duration::from_secs(base_secs + jitter_secs)
}

/// Picks a delay in `[backoff / 2, backoff]` so that nodes restarted together do not
/// probe the origin in lockstep, while the delay never exceeds the backoff.
fn jittered_retry_delay(backoff: Duration) -> Duration {
    let backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(rand::rng().random_range(backoff_ms / 2..=backoff_ms))
}

/// Refresh cadence: exponential retries while any domain still has the default
/// profile, the regular period once every domain has a fetched one.
struct RefreshSchedule {
    retry_backoff: Duration,
}

impl RefreshSchedule {
    fn new() -> Self {
        Self {
            retry_backoff: TLS_FRONT_RETRY_INITIAL,
        }
    }

    fn next_delay(&mut self, has_default_profiles: bool) -> Duration {
        if !has_default_profiles {
            self.retry_backoff = TLS_FRONT_RETRY_INITIAL;
            return regular_refresh_delay();
        }
        let delay = jittered_retry_delay(self.retry_backoff);
        self.retry_backoff = self
            .retry_backoff
            .saturating_mul(2)
            .min(TLS_FRONT_RETRY_MAX);
        delay
    }
}

/// Retries only the domains without a fetched profile, so origins that already
/// answered are not probed more often than the regular refresh.
async fn run_refresh_loop(context: TlsFetchContext) {
    let mut schedule = RefreshSchedule::new();
    loop {
        let pending = context
            .cache
            .default_profile_domains(&context.domains)
            .await;
        tokio::time::sleep(schedule.next_delay(!pending.is_empty())).await;
        if pending.is_empty() {
            context
                .fetch_all_with_budget("TLS emulation refresh failed")
                .await;
        } else {
            context
                .fetch_with_budget(&pending, "TLS emulation retry failed")
                .await;
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
    full_cert_budget: Arc<TlsFullCertBudget>,
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

    let cache = Arc::new(TlsFrontCache::new_with_full_cert_budget(
        tls_domains,
        config.censorship.fake_cert_len,
        &config.censorship.tls_front_dir,
        full_cert_budget,
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

    let best_effort_initial_fetch = match policy {
        TlsBootstrapPolicy::BestEffort => true,
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
            false
        }
    };

    let refresh_context = fetch_context;
    let fake_cert_len = config.censorship.fake_cert_len;
    // The best-effort initial fetch runs on the refresh task so that a retry
    // never overlaps it.
    task_scope.spawn(async move {
        if best_effort_initial_fetch {
            refresh_context
                .fetch_all_with_budget("TLS emulation initial fetch failed")
                .await;
            for domain in refresh_context
                .cache
                .default_profile_domains(&refresh_context.domains)
                .await
            {
                warn!(
                    domain = %domain,
                    timeout_ms = refresh_context.strategy.total_budget.as_millis(),
                    fake_cert_len,
                    "TLS-front fetch not ready within timeout; using cache/default fake cert fallback"
                );
            }
        }
        run_refresh_loop(refresh_context).await;
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
    fn refresh_schedule_retries_default_profiles_with_capped_backoff() {
        let mut schedule = RefreshSchedule::new();
        let expected_backoff_secs = [30, 60, 120, 240, 480, 600, 600];
        for backoff_secs in expected_backoff_secs {
            let delay = schedule.next_delay(true);
            let backoff = Duration::from_secs(backoff_secs);
            assert!(
                delay >= backoff / 2 && delay <= backoff,
                "retry delay {delay:?} outside jitter window of {backoff:?}"
            );
        }
    }

    #[test]
    fn refresh_schedule_returns_to_regular_period_and_resets_backoff() {
        let mut schedule = RefreshSchedule::new();
        for _ in 0..4 {
            schedule.next_delay(true);
        }

        let regular = schedule.next_delay(false);
        assert!(regular >= Duration::from_secs(4 * 3600));
        assert!(regular <= Duration::from_secs(8 * 3600));

        assert!(schedule.next_delay(true) <= TLS_FRONT_RETRY_INITIAL);
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
            Arc::new(TlsFullCertBudget::new()),
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
            Arc::new(TlsFullCertBudget::new()),
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
            Arc::new(TlsFullCertBudget::new()),
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

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn best_effort_retries_failed_domain_before_regular_refresh() {
        let cache_dir = tempfile::tempdir().unwrap();
        let origin_dir = tempfile::tempdir().unwrap();
        let origin_path = origin_dir.path().join("origin.sock");
        let listener = tokio::net::UnixListener::bind(&origin_path).unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_by_origin = accepted.clone();
        let origin = tokio::spawn(async move {
            // Closing every connection keeps the fetch failing and the profile default.
            while let Ok((stream, _)) = listener.accept().await {
                accepted_by_origin.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        let mut config = test_config(cache_dir.path());
        config.censorship.mask_unix_sock = Some(origin_path.display().to_string());
        let domains = vec![config.censorship.tls_domain.clone()];
        let tracker = Arc::new(StartupTracker::new(1));
        let scope = RuntimeTaskScope::new();

        bootstrap_tls_front(
            &config,
            &domains,
            upstream_manager(&config),
            &tracker,
            scope.clone(),
            Arc::new(TlsFullCertBudget::new()),
            TlsBootstrapPolicy::BestEffort,
        )
        .await
        .unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;
        let after_initial = accepted.load(std::sync::atomic::Ordering::SeqCst);
        assert!(after_initial > 0, "initial fetch must reach the origin");
        tokio::time::sleep(TLS_FRONT_RETRY_INITIAL).await;
        assert!(
            accepted.load(std::sync::atomic::Ordering::SeqCst) > after_initial,
            "a domain without a fetched profile must be retried within the first backoff"
        );

        scope.stop().await;
        origin.abort();
    }
}
