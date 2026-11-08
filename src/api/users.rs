use std::net::IpAddr;

use hyper::StatusCode;

use crate::config::ProxyConfig;
use crate::config::RateLimitBps;
use crate::ip_tracker::UserIpTracker;
use crate::proxy::user_admission::credential_id_from_hex;
use crate::stats::Stats;

use super::ApiShared;
use super::config_store::{
    AccessSection, current_revision, load_config_for_mutation,
    save_access_sections_and_fields_if_revision, save_access_sections_to_disk_if_revision,
};
use super::model::{
    ApiFailure, CreateUserRequest, CreateUserResponse, PatchUserRequest, RotateSecretRequest,
    TlsDomainLink, UserInfo, UserLinks, UserQuotaEntry, UserQuotaListData, is_valid_ad_tag,
    is_valid_user_secret, is_valid_username, parse_optional_expiration, parse_patch_expiration,
    random_user_secret,
};
use super::patch::Patch;

mod create;
mod lifecycle;
mod links;
mod source_deny;
mod update;
mod view;

pub(super) use create::create_user;
pub(super) use lifecycle::{delete_user, rotate_secret};
use links::{build_user_links, empty_user_links};
use source_deny::apply_source_deny;
pub(super) use update::{patch_user, set_user_enabled};
pub(super) use view::{build_user_quota_list, refresh_runtime_view, users_from_config};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod period_tests;

#[cfg(test)]
mod source_deny_tests;
