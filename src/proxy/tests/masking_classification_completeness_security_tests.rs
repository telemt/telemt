use super::*;

#[test]
fn detect_client_type_recognizes_extended_http_probe_verbs() {
    assert_eq!(detect_client_type(b"CONNECT / HTTP/1.1\r\n"), "HTTP");
    assert_eq!(detect_client_type(b"TRACE / HTTP/1.1\r\n"), "HTTP");
    assert_eq!(detect_client_type(b"PATCH / HTTP/1.1\r\n"), "HTTP");
}

#[test]
fn detect_client_type_recognizes_fragmented_http_method_prefixes() {
    assert_eq!(detect_client_type(b"CO"), "HTTP");
    assert_eq!(detect_client_type(b"CON"), "HTTP");
    assert_eq!(detect_client_type(b"TR"), "HTTP");
    assert_eq!(detect_client_type(b"PAT"), "HTTP");
}
