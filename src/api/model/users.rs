use super::*;

#[derive(Serialize)]
pub(in crate::api) struct UserLinks {
    pub(in crate::api) classic: Vec<String>,
    pub(in crate::api) secure: Vec<String>,
    pub(in crate::api) tls: Vec<String>,
    pub(in crate::api) tls_domains: Vec<TlsDomainLink>,
}

#[derive(Serialize)]
pub(in crate::api) struct TlsDomainLink {
    pub(in crate::api) domain: String,
    pub(in crate::api) link: String,
}

#[derive(Serialize)]
pub(in crate::api) struct UserInfo {
    pub(in crate::api) username: String,
    pub(in crate::api) enabled: bool,
    pub(in crate::api) in_runtime: bool,
    pub(in crate::api) user_ad_tag: Option<String>,
    pub(in crate::api) max_tcp_conns: Option<usize>,
    pub(in crate::api) expiration_rfc3339: Option<String>,
    pub(in crate::api) data_quota_bytes: Option<u64>,
    pub(in crate::api) rate_limit_up_bps: Option<u64>,
    pub(in crate::api) rate_limit_down_bps: Option<u64>,
    pub(in crate::api) max_unique_ips: Option<usize>,
    pub(in crate::api) current_connections: u64,
    pub(in crate::api) active_unique_ips: usize,
    pub(in crate::api) active_unique_ips_list: Vec<IpAddr>,
    pub(in crate::api) recent_unique_ips: usize,
    pub(in crate::api) recent_unique_ips_list: Vec<IpAddr>,
    pub(in crate::api) total_octets: u64,
    pub(in crate::api) links: UserLinks,
}

#[derive(Serialize)]
pub(in crate::api) struct UserActiveIps {
    pub(in crate::api) username: String,
    pub(in crate::api) active_ips: Vec<IpAddr>,
}

#[derive(Serialize)]
pub(in crate::api) struct CreateUserResponse {
    pub(in crate::api) user: UserInfo,
    pub(in crate::api) secret: String,
}

#[derive(Serialize)]
pub(in crate::api) struct DeleteUserResponse {
    pub(in crate::api) username: String,
    pub(in crate::api) in_runtime: bool,
}

#[derive(Serialize)]
pub(in crate::api) struct ResetUserQuotaResponse {
    pub(in crate::api) username: String,
    pub(in crate::api) used_bytes: u64,
    pub(in crate::api) last_reset_epoch_secs: u64,
}

#[derive(Serialize)]
pub(in crate::api) struct UserQuotaListData {
    pub(in crate::api) users: Vec<UserQuotaEntry>,
}

#[derive(Serialize)]
pub(in crate::api) struct UserQuotaEntry {
    pub(in crate::api) username: String,
    pub(in crate::api) data_quota_bytes: u64,
    pub(in crate::api) used_bytes: u64,
    pub(in crate::api) last_reset_epoch_secs: u64,
}

#[derive(Deserialize)]
pub(in crate::api) struct CreateUserRequest {
    pub(in crate::api) username: String,
    pub(in crate::api) secret: Option<String>,
    pub(in crate::api) user_ad_tag: Option<String>,
    pub(in crate::api) max_tcp_conns: Option<usize>,
    pub(in crate::api) expiration_rfc3339: Option<String>,
    pub(in crate::api) data_quota_bytes: Option<u64>,
    pub(in crate::api) rate_limit_up_bps: Option<u64>,
    pub(in crate::api) rate_limit_down_bps: Option<u64>,
    pub(in crate::api) max_unique_ips: Option<usize>,
    pub(in crate::api) enabled: Option<bool>,
}

#[derive(Deserialize)]
pub(in crate::api) struct PatchUserRequest {
    pub(in crate::api) secret: Option<String>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(in crate::api) user_ad_tag: Patch<String>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(in crate::api) max_tcp_conns: Patch<usize>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(in crate::api) expiration_rfc3339: Patch<String>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(in crate::api) data_quota_bytes: Patch<u64>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(in crate::api) rate_limit_up_bps: Patch<u64>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(in crate::api) rate_limit_down_bps: Patch<u64>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(in crate::api) max_unique_ips: Patch<usize>,
    #[serde(default, deserialize_with = "patch_field")]
    pub(in crate::api) enabled: Patch<bool>,
}

#[derive(Default, Deserialize)]
pub(in crate::api) struct RotateSecretRequest {
    pub(in crate::api) secret: Option<String>,
}

pub(in crate::api) fn parse_optional_expiration(
    value: Option<&str>,
) -> Result<Option<DateTime<Utc>>, ApiFailure> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(raw)
        .map_err(|_| ApiFailure::bad_request("expiration_rfc3339 must be valid RFC3339"))?;
    Ok(Some(parsed.with_timezone(&Utc)))
}

pub(in crate::api) fn parse_patch_expiration(
    value: &Patch<String>,
) -> Result<Patch<DateTime<Utc>>, ApiFailure> {
    match value {
        Patch::Unchanged => Ok(Patch::Unchanged),
        Patch::Remove => Ok(Patch::Remove),
        Patch::Set(raw) => {
            let parsed = DateTime::parse_from_rfc3339(raw)
                .map_err(|_| ApiFailure::bad_request("expiration_rfc3339 must be valid RFC3339"))?;
            Ok(Patch::Set(parsed.with_timezone(&Utc)))
        }
    }
}

pub(in crate::api) fn is_valid_user_secret(secret: &str) -> bool {
    secret.len() == 32 && secret.chars().all(|c| c.is_ascii_hexdigit())
}

pub(in crate::api) fn is_valid_ad_tag(tag: &str) -> bool {
    tag.len() == 32 && tag.chars().all(|c| c.is_ascii_hexdigit())
}

pub(in crate::api) fn is_valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= MAX_USERNAME_LEN
        && user
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

pub(in crate::api) fn random_user_secret() -> String {
    static API_SECRET_RNG: OnceLock<SecureRandom> = OnceLock::new();
    let rng = API_SECRET_RNG.get_or_init(SecureRandom::new);
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}
