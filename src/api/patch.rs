use serde::Deserialize;

/// Three-state field for JSON Merge Patch semantics on the `PATCH /v1/users/{user}`
/// endpoint.
///
/// `Unchanged` is produced when the JSON body omits the field entirely and tells the
/// handler to leave the corresponding configuration entry untouched. `Remove` is
/// produced when the JSON body sets the field to `null` and instructs the handler to
/// drop the entry from the corresponding access HashMap. `Set` carries an explicit
/// new value, including zero, which is preserved verbatim in the configuration.
#[derive(Debug)]
pub(super) enum Patch<T> {
    Unchanged,
    Remove,
    Set(T),
}

impl<T> Default for Patch<T> {
    fn default() -> Self {
        Self::Unchanged
    }
}

/// Serde deserializer adapter for fields that follow JSON Merge Patch semantics.
///
/// Pair this with `#[serde(default, deserialize_with = "patch_field")]` on a
/// `Patch<T>` field. An omitted field falls back to `Patch::Unchanged` via
/// `Default`; an explicit JSON `null` becomes `Patch::Remove`; any other value
/// becomes `Patch::Set(v)`.
pub(super) fn patch_field<'de, D, T>(deserializer: D) -> Result<Patch<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(|opt| match opt {
        Some(value) => Patch::Set(value),
        None => Patch::Remove,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::model::{PatchUserRequest, parse_patch_expiration};
    use chrono::{TimeZone, Utc};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Holder {
        #[serde(default, deserialize_with = "patch_field")]
        value: Patch<u64>,
    }

    fn parse(json: &str) -> Holder {
        serde_json::from_str(json).expect("valid json")
    }

    #[test]
    fn omitted_field_yields_unchanged() {
        let h = parse("{}");
        assert!(matches!(h.value, Patch::Unchanged));
    }

    #[test]
    fn explicit_null_yields_remove() {
        let h = parse(r#"{"value": null}"#);
        assert!(matches!(h.value, Patch::Remove));
    }

    #[test]
    fn explicit_value_yields_set() {
        let h = parse(r#"{"value": 42}"#);
        assert!(matches!(h.value, Patch::Set(42)));
    }

    #[test]
    fn explicit_zero_yields_set_zero() {
        let h = parse(r#"{"value": 0}"#);
        assert!(matches!(h.value, Patch::Set(0)));
    }

    #[test]
    fn parse_patch_expiration_passes_unchanged_and_remove_through() {
        assert!(matches!(
            parse_patch_expiration(&Patch::Unchanged),
            Ok(Patch::Unchanged)
        ));
        assert!(matches!(
            parse_patch_expiration(&Patch::Remove),
            Ok(Patch::Remove)
        ));
    }

    #[test]
    fn parse_patch_expiration_parses_set_value() {
        let parsed =
            parse_patch_expiration(&Patch::Set("2030-01-02T03:04:05Z".into())).expect("valid");
        match parsed {
            Patch::Set(dt) => {
                assert_eq!(dt, Utc.with_ymd_and_hms(2030, 1, 2, 3, 4, 5).unwrap());
            }
            other => panic!("expected Patch::Set, got {:?}", other),
        }
    }

    #[test]
    fn parse_patch_expiration_rejects_invalid_set_value() {
        assert!(parse_patch_expiration(&Patch::Set("not-a-date".into())).is_err());
    }

    #[test]
    fn patch_user_request_deserializes_mixed_states() {
        let raw = r#"{
            "secret": "00112233445566778899aabbccddeeff",
            "max_tcp_conns": 0,
            "max_unique_ips": null,
            "data_quota_bytes": 1024
        }"#;
        let req: PatchUserRequest = serde_json::from_str(raw).expect("valid json");
        assert_eq!(
            req.secret.as_deref(),
            Some("00112233445566778899aabbccddeeff")
        );
        assert!(matches!(req.max_tcp_conns, Patch::Set(0)));
        assert!(matches!(req.max_unique_ips, Patch::Remove));
        assert!(matches!(req.data_quota_bytes, Patch::Set(1024)));
        assert!(matches!(req.expiration_rfc3339, Patch::Unchanged));
        assert!(matches!(req.user_ad_tag, Patch::Unchanged));
    }
}
