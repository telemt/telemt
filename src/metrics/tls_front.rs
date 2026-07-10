use crate::config::ProxyConfig;
use crate::tls_front::TlsFrontCache;

// Keeps TLS-front per-domain health series bounded for large generated configs.
const TLS_FRONT_PROFILE_HEALTH_MAX_DOMAINS: usize = 256;

fn tls_front_domains(config: &ProxyConfig) -> Vec<String> {
    let mut domains = Vec::with_capacity(1 + config.censorship.tls_domains.len());
    if !config.censorship.tls_domain.is_empty() {
        domains.push(config.censorship.tls_domain.clone());
    }
    for domain in &config.censorship.tls_domains {
        if !domain.is_empty() && !domains.contains(domain) {
            domains.push(domain.clone());
        }
    }
    domains
}

fn prometheus_label_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

pub(super) async fn render_tls_front_profile_health(
    out: &mut String,
    config: &ProxyConfig,
    tls_cache: Option<&TlsFrontCache>,
) {
    use std::fmt::Write;

    let domains = tls_front_domains(config);
    let (health, suppressed) = match (config.censorship.tls_emulation, tls_cache) {
        (true, Some(cache)) => {
            cache
                .profile_health_snapshot(&domains, TLS_FRONT_PROFILE_HEALTH_MAX_DOMAINS)
                .await
        }
        _ => (Vec::new(), domains.len()),
    };

    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_profile_domains TLS front configured profile domains by export status"
    );
    let _ = writeln!(out, "# TYPE telemt_tls_front_profile_domains gauge");
    let _ = writeln!(
        out,
        "telemt_tls_front_profile_domains{{status=\"configured\"}} {}",
        domains.len()
    );
    let _ = writeln!(
        out,
        "telemt_tls_front_profile_domains{{status=\"emitted\"}} {}",
        health.len()
    );
    let _ = writeln!(
        out,
        "telemt_tls_front_profile_domains{{status=\"suppressed\"}} {}",
        suppressed
    );
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_profile_info TLS front profile source and feature flags per configured domain"
    );
    let _ = writeln!(out, "# TYPE telemt_tls_front_profile_info gauge");
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_profile_quality_info TLS front profile quality and key-share group per configured domain"
    );
    let _ = writeln!(out, "# TYPE telemt_tls_front_profile_quality_info gauge");
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_profile_age_seconds Age of cached TLS front profile data per configured domain"
    );
    let _ = writeln!(out, "# TYPE telemt_tls_front_profile_age_seconds gauge");
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_profile_server_hello_bytes TLS front cached ServerHello record body bytes per configured domain"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_tls_front_profile_server_hello_bytes gauge"
    );
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_profile_server_hello_extensions TLS front cached visible ServerHello extension count per configured domain"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_tls_front_profile_server_hello_extensions gauge"
    );
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_profile_app_data_records TLS front cached app-data record count per configured domain"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_tls_front_profile_app_data_records gauge"
    );
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_profile_ticket_records TLS front cached ticket-like tail record count per configured domain"
    );
    let _ = writeln!(out, "# TYPE telemt_tls_front_profile_ticket_records gauge");
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_profile_change_cipher_spec_records TLS front cached ChangeCipherSpec record count per configured domain"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_tls_front_profile_change_cipher_spec_records gauge"
    );
    let _ = writeln!(
        out,
        "# HELP telemt_tls_front_profile_app_data_bytes TLS front cached total app-data bytes per configured domain"
    );
    let _ = writeln!(out, "# TYPE telemt_tls_front_profile_app_data_bytes gauge");

    for item in health {
        let domain = prometheus_label_value(&item.domain);
        let _ = writeln!(
            out,
            "telemt_tls_front_profile_info{{domain=\"{}\",source=\"{}\",is_default=\"{}\",has_cert_info=\"{}\",has_cert_payload=\"{}\"}} 1",
            domain, item.source, item.is_default, item.has_cert_info, item.has_cert_payload
        );
        let _ = writeln!(
            out,
            "telemt_tls_front_profile_quality_info{{domain=\"{}\",quality=\"{}\",key_share_group=\"{}\"}} 1",
            domain, item.quality, item.key_share_group
        );
        let _ = writeln!(
            out,
            "telemt_tls_front_profile_age_seconds{{domain=\"{}\"}} {}",
            domain, item.age_seconds
        );
        let _ = writeln!(
            out,
            "telemt_tls_front_profile_server_hello_bytes{{domain=\"{}\"}} {}",
            domain, item.server_hello_record_len
        );
        let _ = writeln!(
            out,
            "telemt_tls_front_profile_server_hello_extensions{{domain=\"{}\"}} {}",
            domain, item.server_hello_extensions
        );
        let _ = writeln!(
            out,
            "telemt_tls_front_profile_app_data_records{{domain=\"{}\"}} {}",
            domain, item.app_data_records
        );
        let _ = writeln!(
            out,
            "telemt_tls_front_profile_ticket_records{{domain=\"{}\"}} {}",
            domain, item.ticket_records
        );
        let _ = writeln!(
            out,
            "telemt_tls_front_profile_change_cipher_spec_records{{domain=\"{}\"}} {}",
            domain, item.change_cipher_spec_count
        );
        let _ = writeln!(
            out,
            "telemt_tls_front_profile_app_data_bytes{{domain=\"{}\"}} {}",
            domain, item.total_app_data_len
        );
    }
}
