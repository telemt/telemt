use std::time::SystemTime;
use serde::{Serialize, Deserialize};

/// Parsed representation of an unencrypted TLS ServerHello.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedServerHello {
    pub version: [u8; 2],
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: [u8; 2],
    pub compression: u8,
    pub extensions: Vec<TlsExtension>,
}

/// Generic TLS extension container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExtension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

/// Basic certificate metadata (optional, informative).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCertificateInfo {
    pub not_after_unix: Option<i64>,
    pub not_before_unix: Option<i64>,
    pub issuer_cn: Option<String>,
    pub subject_cn: Option<String>,
    pub san_names: Vec<String>,
}

/// TLS certificate payload captured from profiled upstream.
///
/// `certificate_message` stores an encoded TLS 1.3 Certificate handshake
/// message body that can be replayed as opaque ApplicationData bytes in FakeTLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertPayload {
    pub cert_chain_der: Vec<Vec<u8>>,
    pub certificate_message: Vec<u8>,
}

/// Provenance of the cached TLS behavior profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsProfileSource {
    /// Built from hardcoded defaults or legacy cache entries.
    #[default]
    Default,
    /// Derived from raw TLS record capture only.
    Raw,
    /// Derived from rustls-only metadata fallback.
    Rustls,
    /// Merged from raw TLS capture and rustls certificate metadata.
    Merged,
}

/// Coarse-grained TLS response behavior captured per SNI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsBehaviorProfile {
    /// Number of ChangeCipherSpec records observed before encrypted flight.
    #[serde(default = "default_change_cipher_spec_count")]
    pub change_cipher_spec_count: u8,
    /// Sizes of the primary encrypted flight records carrying cert-like payload.
    #[serde(default)]
    pub app_data_record_sizes: Vec<usize>,
    /// Sizes of small tail ApplicationData records that look like tickets.
    #[serde(default)]
    pub ticket_record_sizes: Vec<usize>,
    /// Source of this behavior profile.
    #[serde(default)]
    pub source: TlsProfileSource,
}

fn default_change_cipher_spec_count() -> u8 {
    1
}

impl Default for TlsBehaviorProfile {
    fn default() -> Self {
        Self {
            change_cipher_spec_count: default_change_cipher_spec_count(),
            app_data_record_sizes: Vec::new(),
            ticket_record_sizes: Vec::new(),
            source: TlsProfileSource::Default,
        }
    }
}

/// Cached data per SNI used by the emulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTlsData {
    pub server_hello_template: ParsedServerHello,
    pub cert_info: Option<ParsedCertificateInfo>,
    #[serde(default)]
    pub cert_payload: Option<TlsCertPayload>,
    pub app_data_records_sizes: Vec<usize>,
    pub total_app_data_len: usize,
    #[serde(default)]
    pub behavior_profile: TlsBehaviorProfile,
    #[serde(default = "now_system_time", skip_serializing, skip_deserializing)]
    pub fetched_at: SystemTime,
    pub domain: String,
}

fn now_system_time() -> SystemTime {
    SystemTime::now()
}

/// Result of attempting to fetch real TLS artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFetchResult {
    pub server_hello_parsed: ParsedServerHello,
    pub app_data_records_sizes: Vec<usize>,
    pub total_app_data_len: usize,
    #[serde(default)]
    pub behavior_profile: TlsBehaviorProfile,
    pub cert_info: Option<ParsedCertificateInfo>,
    pub cert_payload: Option<TlsCertPayload>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_tls_data_deserializes_without_behavior_profile() {
        let json = r#"
        {
            "server_hello_template": {
                "version": [3, 3],
                "random": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "session_id": [],
                "cipher_suite": [19, 1],
                "compression": 0,
                "extensions": []
            },
            "cert_info": null,
            "cert_payload": null,
            "app_data_records_sizes": [1024],
            "total_app_data_len": 1024,
            "domain": "example.com"
        }
        "#;

        let cached: CachedTlsData = serde_json::from_str(json).unwrap();
        assert_eq!(cached.behavior_profile.change_cipher_spec_count, 1);
        assert!(cached.behavior_profile.app_data_record_sizes.is_empty());
        assert!(cached.behavior_profile.ticket_record_sizes.is_empty());
        assert_eq!(cached.behavior_profile.source, TlsProfileSource::Default);
    }
}
