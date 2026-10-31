use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SNAPSHOT: AtomicU64 = AtomicU64::new(1);

/// Builds the immutable WEB routing and decoy snapshot for one generation.
pub(in crate::config::load) fn rebuild(config: &mut ProxyConfig) -> Result<()> {
    let auth = config.runtime_user_auth().ok_or_else(|| {
        ProxyError::Config("WEB runtime requires the user authentication snapshot".to_string())
    })?;
    let snapshot_id = NEXT_SNAPSHOT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| ProxyError::Config("WEB snapshot identity exhausted".to_string()))?;
    let mut wildcards = BTreeMap::new();
    let mut catch_all = None;
    let mut runtime_vhosts = BTreeMap::new();
    let mut runtime_profiles = Vec::new();
    let mut runtime_capabilities = Vec::new();
    let mut static_files = 0usize;
    let mut static_bytes = 0usize;

    let carrier_candidates: Arc<[WebCarrier]> = config.web.carrier_candidates().into();
    for (vhost_idx, vhost) in config.web.vhosts.iter().enumerate() {
        let decoy = Arc::new(build_decoy(
            config,
            vhost_idx,
            vhost,
            &config.web.limits,
            &mut static_files,
            &mut static_bytes,
        )?);
        let mut host_profiles: Vec<_> = vhost
            .host
            .iter()
            .chain(vhost.hosts.iter().flatten())
            .filter(|host| !host.starts_with('*'))
            .map(|host| {
                (
                    host,
                    Vec::with_capacity(vhost.profiles.len()),
                    Vec::with_capacity(vhost.profiles.len()),
                    HashSet::with_capacity(vhost.profiles.len()),
                )
            })
            .collect();
        let has_wildcards = vhost
            .host
            .iter()
            .chain(vhost.hosts.iter().flatten())
            .any(|host| host.starts_with('*'));
        let mut shared_profiles = Vec::new();
        let mut contexts = HashSet::new();
        for profile in &vhost.profiles {
            let user_id = auth.user_id_by_name(&profile.user).ok_or_else(|| {
                ProxyError::Config(format!(
                    "WEB profile references unknown access user `{}`",
                    profile.user
                ))
            })?;
            let auth_entry = auth.entry_by_id(user_id).ok_or_else(|| {
                ProxyError::Config("WEB profile user snapshot is inconsistent".to_string())
            })?;
            let (client_secret, client_secret_len) =
                client_secret(auth_entry.secret, profile.secret_mode);
            let key_fingerprint = debug_key_fingerprint(&client_secret[..client_secret_len]);
            let shared = Arc::new(WebRuntimeProfileShared {
                derivation_context: wildcard::derivation_context(
                    &client_secret[..client_secret_len],
                    vhost.base_path.as_bytes(),
                ),
                public_addr: vhost.public_addr,
                user: profile.user.clone(),
                credential_id: auth_entry.credential_id,
                secret_mode: profile.secret_mode,
                carrier: config.web.carrier,
                carrier_negotiation_enabled: config.web.carrier_negotiation_enabled(),
                carrier_learning: config.web.carrier_negotiation_enabled()
                    && config.web.carrier_learning,
                carriers: Arc::clone(&carrier_candidates),
                carrier_negotiation_deadlines_secs: config
                    .web
                    .timeouts
                    .carrier_negotiation_deadlines_secs,
                key_fingerprint,
                max_sessions: profile
                    .max_sessions
                    .unwrap_or(config.web.limits.max_sessions_global),
                max_streams: profile
                    .max_streams
                    .unwrap_or(config.web.limits.max_streams_global),
                max_streams_per_session: profile
                    .max_streams_per_session
                    .unwrap_or(config.web.limits.max_streams_per_session),
            });
            if has_wildcards {
                if !contexts.insert(shared.derivation_context) {
                    return Err(ProxyError::Config(
                        "WEB wildcard group contains duplicate client capabilities".to_string(),
                    ));
                }
                shared_profiles.push(Arc::clone(&shared));
            }
            // Only host-bound bindings and capability indexes expand with the alias count.
            for (host, profiles, capability_table, capabilities) in &mut host_profiles {
                let capability = derive_web_capability(
                    &client_secret[..client_secret_len],
                    host.as_bytes(),
                    vhost.base_path.as_bytes(),
                )?;
                if !capabilities.insert(capability) {
                    return Err(ProxyError::Config(format!(
                        "WEB vhost `{host}` contains profiles with the same client capability"
                    )));
                }
                profiles.push(Arc::new(WebRuntimeProfile {
                    host: (*host).clone(),
                    capability,
                    shared: Arc::clone(&shared),
                }));
                capability_table.push(capability);
            }
        }
        if has_wildcards {
            let template = Arc::new(WebRuntimeVhost {
                wildcard: Some(WebRuntimeWildcard {
                    group_id: vhost_idx,
                    profiles: shared_profiles,
                }),
                #[cfg(test)]
                host: String::new(),
                base: if vhost.base_path.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{}/", vhost.base_path)
                },
                decoy_fasttrack_mode: config.web.decoy_fasttrack_mode,
                decoy: Arc::clone(&decoy),
                decoy_header_secs: config.web.timeouts.decoy_header_secs,
                profiles: Vec::new(),
                capabilities: Box::new([]),
            });
            for selector in vhost.host.iter().chain(vhost.hosts.iter().flatten()) {
                if selector == "*" {
                    catch_all = Some(Arc::clone(&template));
                } else if let Some(suffix) = selector.strip_prefix("*.") {
                    wildcards.insert(suffix.to_string(), Arc::clone(&template));
                }
            }
        }
        for (host, profiles, capability_table, _) in host_profiles {
            runtime_capabilities.extend(capability_table.iter().copied());
            runtime_profiles.extend(profiles.iter().cloned());
            runtime_vhosts.insert(
                host.clone(),
                Arc::new(WebRuntimeVhost {
                    wildcard: None,
                    #[cfg(test)]
                    host: host.clone(),
                    base: if vhost.base_path.is_empty() {
                        "/".to_string()
                    } else {
                        format!("/{}/", vhost.base_path)
                    },
                    decoy_fasttrack_mode: config.web.decoy_fasttrack_mode,
                    decoy: Arc::clone(&decoy),
                    decoy_header_secs: config.web.timeouts.decoy_header_secs,
                    profiles,
                    capabilities: capability_table.into_boxed_slice(),
                }),
            );
        }
    }

    config.web.runtime = Some(Arc::new(WebRuntimeConfig {
        snapshot_id,
        wildcards,
        catch_all,
        vhosts: runtime_vhosts,
        profiles: runtime_profiles,
        capabilities: runtime_capabilities.into_boxed_slice(),
    }));
    Ok(())
}
