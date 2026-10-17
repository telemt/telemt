use super::*;

// A length-delimited full digest fences secret, mode and endpoint changes without
// performing HMAC while a process session registry is locked.
pub(super) fn derivation_context(secret: &[u8], base: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"telemt-web-derivation-context-v1\0");
    digest.update([if base.is_empty() { 1 } else { 2 }]);
    digest.update((secret.len() as u64).to_be_bytes());
    digest.update(secret);
    digest.update((base.len() as u64).to_be_bytes());
    digest.update(base);
    digest.finalize().into()
}

impl ProxyConfig {
    /// Derives one complete bounded table after the process HMAC budget is reserved.
    pub(crate) fn wildcard_capabilities(
        &self,
        vhost: &WebRuntimeVhost,
        host: &str,
    ) -> Result<Box<[[u8; 32]]>> {
        let group = vhost
            .wildcard
            .as_ref()
            .ok_or_else(|| ProxyError::Config("WEB wildcard template is missing".to_string()))?;
        let auth = self.runtime_user_auth().ok_or_else(|| {
            ProxyError::Config("WEB authentication snapshot is missing".to_string())
        })?;
        let mut capabilities = Vec::with_capacity(group.profiles.len());
        for profile in &group.profiles {
            let entry = auth
                .user_id_by_name(&profile.user)
                .and_then(|id| auth.entry_by_id(id))
                .ok_or_else(|| {
                    ProxyError::Config(
                        "WEB wildcard authentication snapshot is inconsistent".to_string(),
                    )
                })?;
            let (secret, len) = client_secret(entry.secret, profile.secret_mode);
            capabilities.push(derive_web_capability(
                &secret[..len],
                host.as_bytes(),
                vhost.base.trim_matches('/').as_bytes(),
            )?);
        }
        Ok(capabilities.into_boxed_slice())
    }
}
