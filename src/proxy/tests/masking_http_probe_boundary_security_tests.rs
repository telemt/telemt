use super::*;

#[test]
fn exact_four_byte_http_tokens_are_classified() {
    for token in [
        b"GET ".as_ref(),
        b"POST".as_ref(),
        b"HEAD".as_ref(),
        b"PUT ".as_ref(),
        b"PRI ".as_ref(),
    ] {
        assert!(
            is_http_probe(token),
            "exact 4-byte token must be classified as HTTP probe: {:?}",
            token
        );
    }
}

#[test]
fn exact_four_byte_non_http_tokens_are_not_classified() {
    for token in [
        b"GEX ".as_ref(),
        b"POXT".as_ref(),
        b"HEA/".as_ref(),
        b"PU\0 ".as_ref(),
        b"PRI/".as_ref(),
    ] {
        assert!(
            !is_http_probe(token),
            "non-HTTP 4-byte token must not be classified: {:?}",
            token
        );
    }
}

#[test]
fn detect_client_type_keeps_http_label_for_minimal_four_byte_http_prefixes() {
    assert_eq!(detect_client_type(b"GET "), "HTTP");
    assert_eq!(detect_client_type(b"PRI "), "HTTP");
}

#[test]
fn exact_long_http_tokens_are_classified() {
    for token in [b"CONNECT".as_ref(), b"TRACE".as_ref(), b"PATCH".as_ref()] {
        assert!(
            is_http_probe(token),
            "exact long HTTP token must be classified as HTTP probe: {:?}",
            token
        );
    }
}

#[test]
fn detect_client_type_keeps_http_label_for_exact_long_http_tokens() {
    assert_eq!(detect_client_type(b"CONNECT"), "HTTP");
    assert_eq!(detect_client_type(b"TRACE"), "HTTP");
    assert_eq!(detect_client_type(b"PATCH"), "HTTP");
}

#[test]
fn light_fuzz_four_byte_ascii_noise_not_misclassified() {
    // Deterministic pseudo-fuzz over 4-byte printable ASCII inputs.
    let mut x = 0xA17C_93E5u32;
    for _ in 0..2048 {
        let mut token = [0u8; 4];
        for byte in &mut token {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            *byte = 32 + ((x & 0x3F) as u8); // printable ASCII subset
        }

        if [b"GET ", b"POST", b"HEAD", b"PUT ", b"PRI "]
            .iter()
            .any(|m| token.as_slice() == *m)
        {
            continue;
        }

        assert!(
            !is_http_probe(&token),
            "pseudo-fuzz noise misclassified as HTTP probe: {:?}",
            token
        );
    }
}
