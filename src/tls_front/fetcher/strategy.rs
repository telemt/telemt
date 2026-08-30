use super::*;

/// Fetch real TLS metadata with an adaptive multi-profile strategy.
pub async fn fetch_real_tls_with_strategy(
    host: &str,
    port: u16,
    sni: &str,
    strategy: &TlsFetchStrategy,
    upstream: Option<std::sync::Arc<crate::transport::UpstreamManager>>,
    scope: Option<&str>,
    proxy_protocol: u8,
    unix_sock: Option<&str>,
) -> Result<TlsFetchResult> {
    let attempt_timeout = strategy.attempt_timeout.max(Duration::from_millis(1));
    let total_budget = strategy.total_budget.max(Duration::from_millis(1));
    let started_at = Instant::now();
    let cache_key = profile_cache_key(
        host,
        port,
        sni,
        upstream.as_ref(),
        scope,
        proxy_protocol,
        unix_sock,
    );
    let profiles = order_profiles(strategy, Some(&cache_key), started_at);

    let mut raw_result = None;
    let mut raw_last_error: Option<anyhow::Error> = None;
    let mut raw_last_error_kind = FetchErrorKind::Other;
    let mut selected_profile = None;

    for profile in profiles {
        let elapsed = started_at.elapsed();
        if elapsed >= total_budget {
            break;
        }
        let timeout_for_attempt = attempt_timeout.min(total_budget - elapsed);
        debug!(
            sni = %sni,
            profile = profile.as_str(),
            alpn = ?profile_alpn_labels(profile),
            grease_enabled = strategy.grease_enabled,
            deterministic = strategy.deterministic,
            "TLS fetch ClientHello params (raw)"
        );

        match fetch_via_raw_tls(
            host,
            port,
            sni,
            timeout_for_attempt,
            upstream.clone(),
            scope,
            proxy_protocol,
            unix_sock,
            strategy.strict_route,
            profile,
            strategy.grease_enabled,
            strategy.deterministic,
        )
        .await
        {
            Ok(res) => {
                selected_profile = Some(profile);
                raw_result = Some(res);
                break;
            }
            Err(err) => {
                let kind = classify_fetch_error(&err);
                warn!(
                    sni = %sni,
                    profile = profile.as_str(),
                    error_kind = ?kind,
                    error = %err,
                    "Raw TLS fetch attempt failed"
                );
                raw_last_error_kind = kind;
                raw_last_error = Some(err);
                if strategy.strict_route && matches!(kind, FetchErrorKind::Route) {
                    break;
                }
            }
        }
    }

    if let Some(profile) = selected_profile {
        remember_profile_success(strategy, Some(cache_key), profile, Instant::now());
    }

    if raw_result.is_none()
        && strategy.strict_route
        && matches!(raw_last_error_kind, FetchErrorKind::Route)
    {
        if let Some(err) = raw_last_error {
            return Err(err);
        }
        return Err(anyhow!("TLS fetch strict-route failure"));
    }

    let elapsed = started_at.elapsed();
    if elapsed >= total_budget {
        return match raw_result {
            Some(raw) => Ok(raw),
            None => {
                Err(raw_last_error.unwrap_or_else(|| anyhow!("TLS fetch total budget exhausted")))
            }
        };
    }

    let rustls_timeout = attempt_timeout.min(total_budget - elapsed);
    let rustls_profile = selected_profile.unwrap_or(TlsFetchProfile::ModernChromeLike);
    let rustls_alpn_protocols = profile_alpn(rustls_profile);
    debug!(
        sni = %sni,
        profile = rustls_profile.as_str(),
        alpn = ?profile_alpn_labels(rustls_profile),
        grease_enabled = strategy.grease_enabled,
        deterministic = strategy.deterministic,
        "TLS fetch ClientHello params (rustls)"
    );
    let rustls_result = fetch_via_rustls(
        host,
        port,
        sni,
        rustls_timeout,
        upstream,
        scope,
        proxy_protocol,
        unix_sock,
        strategy.strict_route,
        rustls_alpn_protocols,
    )
    .await;

    match rustls_result {
        Ok(rustls) => {
            if let Some(mut raw) = raw_result {
                raw.cert_info = rustls.cert_info;
                raw.cert_payload = rustls.cert_payload;
                raw.behavior_profile.source = TlsProfileSource::Merged;
                raw.behavior_profile
                    .refresh_server_hello_summary(&raw.server_hello_parsed);
                debug!(sni = %sni, "Fetched TLS metadata via adaptive raw probe + rustls cert chain");
                Ok(raw)
            } else {
                Ok(rustls)
            }
        }
        Err(err) => {
            if let Some(raw) = raw_result {
                warn!(sni = %sni, error = %err, "Rustls cert fetch failed, using raw TLS metadata only");
                Ok(raw)
            } else if let Some(raw_err) = raw_last_error {
                Err(anyhow!("TLS fetch failed (raw: {raw_err}; rustls: {err})"))
            } else {
                Err(err)
            }
        }
    }
}
