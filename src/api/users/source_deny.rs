use super::*;
use crate::api::config_store::FieldEdit;

/// Source-deny intent changes only desired TOML; generation admission remains untouched.
pub(super) fn apply_source_deny(
    cfg: &mut ProxyConfig,
    username: &str,
    patch: Patch<Vec<ipnetwork::IpNetwork>>,
) -> Result<Vec<FieldEdit>, ApiFailure> {
    let value = match patch {
        Patch::Unchanged => return Ok(Vec::new()),
        Patch::Remove => {
            cfg.access.user_source_deny.remove(username);
            None
        }
        Patch::Set(nets) => {
            let value = toml::Value::try_from(&nets)
                .map_err(|_| ApiFailure::internal("Cannot render source-deny list"))?;
            cfg.access
                .user_source_deny
                .insert(username.to_owned(), nets);
            Some(value)
        }
    };
    Ok(vec![FieldEdit::new(
        &["access", "user_source_deny", username],
        value,
    )])
}
