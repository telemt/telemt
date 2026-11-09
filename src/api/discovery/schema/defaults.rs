use serde_json::{Value, json};

use crate::config::{ListenerConfig, ProxyConfig, UpstreamConfig, WebVhostConfig};

/// Supplies child defaults for otherwise empty collections. Required/example
/// values are never projected; their catalog default kind excludes them.
pub(super) fn typed_defaults() -> Result<Value, String> {
    let mut config = ProxyConfig::default();
    // Even the repository's built-in example credential is not schema data.
    config.access.users.clear();
    let mut root = serde_json::to_value(config).map_err(|error| error.to_string())?;
    let listener: ListenerConfig =
        serde_json::from_value(json!({"ip": "127.0.0.1"})).map_err(|error| error.to_string())?;
    let upstreams: Vec<UpstreamConfig> = serde_json::from_value(json!([
        {"type": "direct"},
        {"type": "socks4", "address": "127.0.0.1:1080"},
        {"type": "socks5", "address": "127.0.0.1:1080"},
        {"type": "shadowsocks", "url": "ss://schema-example"}
    ]))
    .map_err(|error| error.to_string())?;
    let vhosts: Vec<WebVhostConfig> = serde_json::from_value(json!([
        {
            "host": "schema.example", "public_addr": "127.0.0.1:443",
            "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:8080"},
            "profiles": [{"user": "schema-example", "secret_mode": "plain"}]
        },
        {
            "hosts": ["schema.example"], "public_addr": "127.0.0.1:443",
            "decoy": {"mode": "static_directory", "directory": "/schema-example"}
        }
    ]))
    .map_err(|error| error.to_string())?;
    // Collection roots retain their actual empty default. The separate child
    // tree is selected only by paths containing an array element marker.
    root["_elements"] = json!({
        "server": {"listeners": [listener]},
        "upstreams": upstreams,
        "web": {"vhosts": vhosts}
    });
    Ok(root)
}
