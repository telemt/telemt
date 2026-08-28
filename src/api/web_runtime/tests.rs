use super::*;

use hyper::header::HeaderValue;

#[test]
fn route_table_keeps_status_read_only_and_controls_post_only() {
    assert_eq!(allowed_methods(STATUS_PATH), Some(ALLOW_GET));
    assert_eq!(allowed_methods(SESSIONS_PATH), Some(ALLOW_GET));
    assert_eq!(allowed_methods(CLOSE_PATH), Some(ALLOW_POST));
    assert_eq!(allowed_methods(DEBUG_CLEAR_PATH), Some(ALLOW_POST));
    assert_eq!(allowed_methods(LEARNING_RESET_PATH), Some(ALLOW_POST));
    assert_eq!(allowed_methods(LIFECYCLE_PAUSE_PATH), Some(ALLOW_POST));
    assert_eq!(allowed_methods(LIFECYCLE_DRAIN_PATH), Some(ALLOW_POST));
    assert_eq!(allowed_methods(LIFECYCLE_RESUME_PATH), Some(ALLOW_POST));
    assert_eq!(
        allowed_methods("/v1/runtime/web/sessions/ws1.instance.0000000000000001"),
        Some(ALLOW_GET)
    );
}

#[test]
fn control_content_type_is_exact_and_single() {
    let exact = Request::builder()
        .header(CONTENT_TYPE, "application/json")
        .body(())
        .unwrap();
    assert!(require_json_content_type(&exact).is_ok());

    let parameterized = Request::builder()
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(())
        .unwrap();
    assert!(require_json_content_type(&parameterized).is_err());

    let mut duplicated = Request::builder()
        .header(CONTENT_TYPE, "application/json")
        .body(())
        .unwrap();
    duplicated
        .headers_mut()
        .append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    assert!(require_json_content_type(&duplicated).is_err());
}

#[test]
fn drain_timeout_is_bounded_to_the_public_contract() {
    assert_eq!(drain_timeout(1).unwrap(), Duration::from_secs(1));
    assert_eq!(drain_timeout(3600).unwrap(), Duration::from_secs(3600));
    assert!(drain_timeout(0).is_err());
    assert!(drain_timeout(3601).is_err());
}
