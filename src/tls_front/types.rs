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

/// Cached data per SNI used by the emulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTlsData {
    pub server_hello_template: ParsedServerHello,
    pub cert_info: Option<ParsedCertificateInfo>,
    pub app_data_records_sizes: Vec<usize>,
    pub total_app_data_len: usize,
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
    pub cert_info: Option<ParsedCertificateInfo>,
}
