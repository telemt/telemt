use super::*;

#[derive(Debug)]
/// One rejected configuration path and its optional nearest known key.
pub(super) struct UnknownConfigKey {
    /// Fully qualified configuration path.
    pub(super) path: String,
    /// Nearest known key when edit distance is sufficiently small.
    pub(super) suggestion: Option<String>,
}

fn table_at<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Table> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_table()
}

/// Reads strict-key enforcement without deserializing the full configuration.
pub(super) fn is_strict_config(parsed_toml: &toml::Value) -> bool {
    table_at(parsed_toml, &["general"])
        .and_then(|table| table.get("config_strict"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

fn known_config_keys_for_suggestion() -> Vec<&'static str> {
    let mut keys = Vec::new();
    for group in [
        TOP_LEVEL_CONFIG_KEYS,
        GENERAL_CONFIG_KEYS,
        NETWORK_CONFIG_KEYS,
        SERVER_CONFIG_KEYS,
        API_CONFIG_KEYS,
        CONNTRACK_CONTROL_CONFIG_KEYS,
        LISTENER_CONFIG_KEYS,
        WEB_CONFIG_KEYS,
        WEB_RETRY_JITTER_KEYS,
        WEB_LIMITS_CONFIG_KEYS,
        WEB_WILDCARD_LIMITS_CONFIG_KEYS,
        WEB_DEBUG_CONFIG_KEYS,
        WEB_TIMEOUTS_CONFIG_KEYS,
        WEB_VHOST_CONFIG_KEYS,
        WEB_DECOY_CONFIG_KEYS,
        WEB_PROFILE_CONFIG_KEYS,
        TIMEOUTS_CONFIG_KEYS,
        CENSORSHIP_CONFIG_KEYS,
        TLS_FETCH_CONFIG_KEYS,
        ACCESS_CONFIG_KEYS,
        RATE_LIMIT_BPS_CONFIG_KEYS,
        UPSTREAM_CONFIG_KEYS,
        PROXY_MODES_CONFIG_KEYS,
        TELEMETRY_CONFIG_KEYS,
        LINKS_CONFIG_KEYS,
        LOGGING_CONFIG_KEYS,
    ] {
        keys.extend_from_slice(group);
    }
    keys
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut curr = vec![0usize; b_chars.len() + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b_chars.iter().enumerate() {
            let replace = if ca == *cb { prev[j] } else { prev[j] + 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(replace);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_chars.len()]
}

fn unknown_key_suggestion(key: &str, known_keys: &[&'static str]) -> Option<String> {
    let normalized = key.to_ascii_lowercase();
    let mut best: Option<(&str, usize)> = None;
    for known in known_keys {
        let distance = levenshtein_distance(&normalized, known);
        let is_better = match best {
            Some((_, best_distance)) => distance < best_distance,
            None => true,
        };
        if distance <= 4 && is_better {
            best = Some((known, distance));
        }
    }
    best.map(|(known, _)| known.to_string())
}

fn push_unknown_keys(
    unknown: &mut Vec<UnknownConfigKey>,
    known_for_suggestion: &[&'static str],
    path: &str,
    table: &toml::Table,
    allowed: &[&str],
) {
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            let full_path = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            unknown.push(UnknownConfigKey {
                path: full_path,
                suggestion: unknown_key_suggestion(key, known_for_suggestion),
            });
        }
    }
}

fn check_known_table(
    parsed_toml: &toml::Value,
    unknown: &mut Vec<UnknownConfigKey>,
    known_for_suggestion: &[&'static str],
    path: &[&str],
    allowed: &[&str],
) {
    if let Some(table) = table_at(parsed_toml, path) {
        push_unknown_keys(
            unknown,
            known_for_suggestion,
            &path.join("."),
            table,
            allowed,
        );
    }
}

fn check_nested_table_value(
    unknown: &mut Vec<UnknownConfigKey>,
    known_for_suggestion: &[&'static str],
    path: String,
    value: &toml::Value,
    allowed: &[&str],
) {
    if let Some(table) = value.as_table() {
        push_unknown_keys(unknown, known_for_suggestion, &path, table, allowed);
    }
}

/// Collects unknown keys across every supported nested configuration table.
pub(super) fn collect_unknown_config_keys(parsed_toml: &toml::Value) -> Vec<UnknownConfigKey> {
    let known_for_suggestion = known_config_keys_for_suggestion();
    let mut unknown = Vec::new();

    if let Some(root) = parsed_toml.as_table() {
        push_unknown_keys(
            &mut unknown,
            &known_for_suggestion,
            "",
            root,
            TOP_LEVEL_CONFIG_KEYS,
        );
    }

    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["general"],
        GENERAL_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["general", "modes"],
        PROXY_MODES_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["general", "telemetry"],
        TELEMETRY_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["general", "links"],
        LINKS_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["logging"],
        LOGGING_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["network"],
        NETWORK_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["server"],
        SERVER_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["server", "api"],
        API_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["server", "admin_api"],
        API_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["server", "conntrack_control"],
        CONNTRACK_CONTROL_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["web"],
        WEB_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["web", "retry_jitter"],
        WEB_RETRY_JITTER_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["web", "limits"],
        WEB_LIMITS_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["web", "limits", "wildcard"],
        WEB_WILDCARD_LIMITS_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["web", "debug"],
        WEB_DEBUG_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["web", "timeouts"],
        WEB_TIMEOUTS_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["timeouts"],
        TIMEOUTS_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["censorship"],
        CENSORSHIP_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["censorship", "tls_fetch"],
        TLS_FETCH_CONFIG_KEYS,
    );
    check_known_table(
        parsed_toml,
        &mut unknown,
        &known_for_suggestion,
        &["access"],
        ACCESS_CONFIG_KEYS,
    );

    if let Some(listeners) = table_at(parsed_toml, &["server"])
        .and_then(|table| table.get("listeners"))
        .and_then(toml::Value::as_array)
    {
        for (idx, listener) in listeners.iter().enumerate() {
            check_nested_table_value(
                &mut unknown,
                &known_for_suggestion,
                format!("server.listeners[{idx}]"),
                listener,
                LISTENER_CONFIG_KEYS,
            );
        }
    }

    if let Some(vhosts) = table_at(parsed_toml, &["web"])
        .and_then(|table| table.get("vhosts"))
        .and_then(toml::Value::as_array)
    {
        for (vhost_idx, vhost) in vhosts.iter().enumerate() {
            check_nested_table_value(
                &mut unknown,
                &known_for_suggestion,
                format!("web.vhosts[{vhost_idx}]"),
                vhost,
                WEB_VHOST_CONFIG_KEYS,
            );
            if let Some(vhost) = vhost.as_table() {
                if let Some(decoy) = vhost.get("decoy") {
                    check_nested_table_value(
                        &mut unknown,
                        &known_for_suggestion,
                        format!("web.vhosts[{vhost_idx}].decoy"),
                        decoy,
                        WEB_DECOY_CONFIG_KEYS,
                    );
                }
                if let Some(profiles) = vhost.get("profiles").and_then(toml::Value::as_array) {
                    for (profile_idx, profile) in profiles.iter().enumerate() {
                        check_nested_table_value(
                            &mut unknown,
                            &known_for_suggestion,
                            format!("web.vhosts[{vhost_idx}].profiles[{profile_idx}]"),
                            profile,
                            WEB_PROFILE_CONFIG_KEYS,
                        );
                    }
                }
            }
        }
    }

    if let Some(upstreams) = parsed_toml.get("upstreams").and_then(toml::Value::as_array) {
        for (idx, upstream) in upstreams.iter().enumerate() {
            check_nested_table_value(
                &mut unknown,
                &known_for_suggestion,
                format!("upstreams[{idx}]"),
                upstream,
                UPSTREAM_CONFIG_KEYS,
            );
        }
    }

    for access_map in ["user_rate_limits", "cidr_rate_limits"] {
        if let Some(table) = table_at(parsed_toml, &["access"])
            .and_then(|access| access.get(access_map))
            .and_then(toml::Value::as_table)
        {
            for (entry_name, value) in table {
                check_nested_table_value(
                    &mut unknown,
                    &known_for_suggestion,
                    format!("access.{access_map}.{entry_name}"),
                    value,
                    RATE_LIMIT_BPS_CONFIG_KEYS,
                );
            }
        }
    }

    unknown
}
