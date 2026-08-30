use super::*;

pub(crate) fn sample_lognormal_percentile_bounded(
    floor: u64,
    ceiling: u64,
    rng: &mut impl Rng,
) -> u64 {
    if ceiling == 0 && floor == 0 {
        return 0;
    }
    if floor > ceiling {
        return ceiling;
    }
    if floor == ceiling {
        return floor;
    }
    let floor_f = floor.max(1) as f64;
    let ceiling_f = ceiling.max(1) as f64;
    let mu = (floor_f.ln() + ceiling_f.ln()) / 2.0;
    // 4.65 ≈ 2 * 2.326 (double-sided z-score for 99th percentile)
    let sigma = ((ceiling_f / floor_f).ln() / 4.65).max(0.01);
    // Box-Muller transform: two uniform samples → one standard normal sample
    let u1: f64 = rng.random_range(f64::MIN_POSITIVE..1.0);
    let u2: f64 = rng.random_range(0.0_f64..std::f64::consts::TAU);
    let normal_sample = (-2.0_f64 * u1.ln()).sqrt() * u2.cos();
    let raw = (mu + sigma * normal_sample).exp();
    if raw.is_finite() {
        (raw as u64).clamp(floor, ceiling)
    } else {
        ((floor_f * ceiling_f).sqrt()) as u64
    }
}

pub(super) fn mask_outcome_target_budget(config: &ProxyConfig) -> Duration {
    if config.censorship.mask_timing_normalization_enabled {
        let floor = config.censorship.mask_timing_normalization_floor_ms;
        let ceiling = config.censorship.mask_timing_normalization_ceiling_ms;
        if floor == 0 {
            if ceiling == 0 {
                return Duration::from_millis(0);
            }
            // floor=0 stays uniform: log-normal cannot model distribution anchored at zero
            let mut rng = rand::rng();
            return Duration::from_millis(rng.random_range(0..=ceiling));
        }
        if ceiling > floor {
            let mut rng = rand::rng();
            return Duration::from_millis(sample_lognormal_percentile_bounded(
                floor, ceiling, &mut rng,
            ));
        }
        // ceiling <= floor: use the larger value (fail-closed: preserve longer delay)
        return Duration::from_millis(floor.max(ceiling));
    }

    MASK_TIMEOUT
}

pub(super) async fn wait_mask_connect_budget_if_needed(started: Instant, config: &ProxyConfig) {
    if config.censorship.mask_timing_normalization_enabled {
        return;
    }

    wait_mask_connect_budget(started).await;
}

pub(super) async fn wait_mask_outcome_budget(started: Instant, config: &ProxyConfig) {
    let target = mask_outcome_target_budget(config);
    let elapsed = started.elapsed();
    if elapsed < target {
        tokio::time::sleep(target - elapsed).await;
    }
}

#[cfg(test)]
mod tls_domain_mask_host_tests {
    use super::{
        mask_host_for_initial_data, mask_tcp_target_for_initial_data, matching_tls_domain_for_sni,
    };
    use crate::config::ProxyConfig;

    fn client_hello_with_sni(sni_host: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(32);
        body.extend_from_slice(&[0x42u8; 32]);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);

        let host_bytes = sni_host.as_bytes();
        let mut sni_payload = Vec::new();
        sni_payload.extend_from_slice(&((host_bytes.len() + 3) as u16).to_be_bytes());
        sni_payload.push(0);
        sni_payload.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni_payload.extend_from_slice(host_bytes);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_payload.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_payload);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let body_len = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&body_len[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn config_with_tls_domains() -> ProxyConfig {
        let mut config = ProxyConfig::default();
        config.censorship.tls_domain = "a.com".to_string();
        config.censorship.tls_domains = vec!["b.com".to_string(), "c.com".to_string()];
        config.censorship.mask_host = None;
        config
    }

    #[test]
    fn matching_tls_domain_accepts_primary_and_extra_domains_case_insensitively() {
        let config = config_with_tls_domains();

        assert_eq!(matching_tls_domain_for_sni(&config, "A.COM"), Some("a.com"));
        assert_eq!(matching_tls_domain_for_sni(&config, "B.COM"), Some("b.com"));
        assert_eq!(matching_tls_domain_for_sni(&config, "unknown.com"), None);
    }

    #[test]
    fn mask_host_preserves_explicit_non_primary_origin() {
        let mut config = config_with_tls_domains();
        config.censorship.mask_host = Some("origin.example".to_string());

        let initial_data = client_hello_with_sni("b.com");

        assert_eq!(
            mask_host_for_initial_data(&config, &initial_data),
            "origin.example"
        );
    }

    #[test]
    fn mask_host_uses_matching_tls_domain_when_mask_host_is_primary_default() {
        let config = config_with_tls_domains();
        let initial_data = client_hello_with_sni("b.com");

        assert_eq!(mask_host_for_initial_data(&config, &initial_data), "b.com");
    }

    #[test]
    fn mask_host_uses_primary_domain_when_dynamic_masking_is_disabled() {
        let mut config = config_with_tls_domains();
        config.censorship.mask_dynamic = false;
        let initial_data = client_hello_with_sni("b.com");

        assert_eq!(mask_host_for_initial_data(&config, &initial_data), "a.com");
    }

    #[test]
    fn exclusive_mask_target_overrides_only_matching_sni() {
        let mut config = config_with_tls_domains();
        config
            .censorship
            .exclusive_mask
            .insert("b.com".to_string(), "origin-b.example:8443".to_string());
        let b_initial_data = client_hello_with_sni("B.COM");
        let c_initial_data = client_hello_with_sni("c.com");

        let b_target = mask_tcp_target_for_initial_data(&config, &b_initial_data);
        let c_target = mask_tcp_target_for_initial_data(&config, &c_initial_data);

        assert_eq!(b_target.host, "origin-b.example");
        assert_eq!(b_target.port, 8443);
        assert_eq!(c_target.host, "c.com");
        assert_eq!(c_target.port, config.censorship.mask_port);
    }
}
