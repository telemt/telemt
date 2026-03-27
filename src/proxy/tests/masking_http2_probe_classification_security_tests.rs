use super::*;

#[test]
fn full_http2_preface_classified_as_http_probe() {
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert!(
        is_http_probe(preface),
        "HTTP/2 connection preface must be classified as HTTP probe"
    );
}

#[test]
fn partial_http2_preface_3_bytes_classified() {
    assert!(
        is_http_probe(b"PRI"),
        "3-byte HTTP/2 preface prefix must be classified"
    );
}

#[test]
fn partial_http2_preface_2_bytes_classified() {
    assert!(
        is_http_probe(b"PR"),
        "2-byte HTTP/2 preface prefix must be classified"
    );
}

#[test]
fn existing_http1_methods_unaffected() {
    for prefix in [
        b"GET / HTTP/1.1\r\n".as_ref(),
        b"POST /api HTTP/1.1\r\n".as_ref(),
        b"CONNECT example.com:443 HTTP/1.1\r\n".as_ref(),
        b"TRACE / HTTP/1.1\r\n".as_ref(),
        b"PATCH / HTTP/1.1\r\n".as_ref(),
    ] {
        assert!(is_http_probe(prefix));
    }
}

#[test]
fn non_http_data_not_classified() {
    for data in [
        b"\x16\x03\x01\x00\xf1".as_ref(),
        b"SSH-2.0-OpenSSH_8.9\r\n".as_ref(),
        b"\x00\x01\x02\x03".as_ref(),
        b"".as_ref(),
        b"P".as_ref(),
    ] {
        assert!(!is_http_probe(data));
    }
}

#[test]
fn light_fuzz_non_http_prefixes_not_misclassified() {
    // Deterministic pseudo-fuzz to exercise classifier edges while avoiding
    // known HTTP method and partial windows.
    let mut x = 0x1234_5678u32;
    for _ in 0..1024 {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        let len = 4 + ((x >> 8) as usize % 12);
        let mut data = vec![0u8; len];
        for byte in &mut data {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            *byte = (x & 0xFF) as u8;
        }

        if [
            b"GET ".as_ref(),
            b"POST".as_ref(),
            b"HEAD".as_ref(),
            b"PUT ".as_ref(),
            b"DELETE".as_ref(),
            b"OPTIONS".as_ref(),
            b"CONNECT".as_ref(),
            b"TRACE".as_ref(),
            b"PATCH".as_ref(),
            b"PRI ".as_ref(),
        ]
        .iter()
        .any(|m| data.starts_with(m))
        {
            continue;
        }

        assert!(
            !is_http_probe(&data),
            "non-http pseudo-fuzz input misclassified: {:?}",
            &data[..data.len().min(8)]
        );
    }
}
