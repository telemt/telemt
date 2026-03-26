use super::*;
use crate::protocol::constants::{TG_DATACENTER_PORT, TG_DATACENTERS_V4};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Mutex;

#[test]
fn common_invalid_override_entries_fallback_to_static_table() {
    let mut cfg = ProxyConfig::default();
    cfg.dc_overrides.insert(
        "2".to_string(),
        vec!["bad-address".to_string(), "still-bad".to_string()],
    );

    let resolved =
        get_dc_addr_static(2, &cfg).expect("fallback to static table must still resolve");
    let expected = SocketAddr::new(TG_DATACENTERS_V4[1], TG_DATACENTER_PORT);
    assert_eq!(resolved, expected);
}

#[test]
fn common_prefer_v6_with_only_ipv4_override_uses_override_instead_of_ignoring_it() {
    let mut cfg = ProxyConfig::default();
    cfg.network.prefer = 6;
    cfg.network.ipv6 = Some(true);
    cfg.dc_overrides
        .insert("3".to_string(), vec!["203.0.113.203:443".to_string()]);

    let resolved =
        get_dc_addr_static(3, &cfg).expect("ipv4 override must be used if no ipv6 override exists");
    assert_eq!(resolved, "203.0.113.203:443".parse::<SocketAddr>().unwrap());
}

#[test]
fn common_scope_hint_rejects_unicode_lookalike_characters() {
    assert_eq!(validated_scope_hint("scope_аlpha"), None);
    assert_eq!(validated_scope_hint("scope_Αlpha"), None);
}

#[cfg(unix)]
#[test]
fn common_anchored_open_rejects_nul_filename() {
    use std::os::unix::ffi::OsStringExt;

    let parent = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!("telemt-direct-relay-nul-{}", std::process::id()));
    std::fs::create_dir_all(&parent).expect("parent directory must be creatable");

    let path = SanitizedUnknownDcLogPath {
        resolved_path: parent.join("placeholder.log"),
        allowed_parent: parent,
        file_name: std::ffi::OsString::from_vec(vec![b'a', 0, b'b']),
    };

    let err = open_unknown_dc_log_append_anchored(&path)
        .expect_err("anchored open must fail on NUL in filename");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[cfg(unix)]
#[test]
fn common_anchored_open_creates_owner_only_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let parent = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!("telemt-direct-relay-perm-{}", std::process::id()));
    std::fs::create_dir_all(&parent).expect("parent directory must be creatable");

    let sanitized = SanitizedUnknownDcLogPath {
        resolved_path: parent.join("unknown-dc.log"),
        allowed_parent: parent.clone(),
        file_name: std::ffi::OsString::from("unknown-dc.log"),
    };

    let mut file = open_unknown_dc_log_append_anchored(&sanitized)
        .expect("anchored open must create regular file");
    use std::io::Write;
    writeln!(file, "dc_idx=1").expect("write must succeed");

    let mode = std::fs::metadata(parent.join("unknown-dc.log"))
        .expect("metadata must be readable")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn common_duplicate_dc_attempts_do_not_consume_unique_slots() {
    let set = Mutex::new(HashSet::new());

    assert!(should_log_unknown_dc_with_set(&set, 100));
    assert!(!should_log_unknown_dc_with_set(&set, 100));
    assert!(should_log_unknown_dc_with_set(&set, 101));
    assert_eq!(set.lock().expect("set lock must be available").len(), 2);
}
