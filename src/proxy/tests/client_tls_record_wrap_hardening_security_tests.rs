use super::*;

#[test]
fn wrap_tls_application_record_empty_payload_emits_zero_length_record() {
    let record = wrap_tls_application_record(&[]);
    assert_eq!(record.len(), 5);
    assert_eq!(record[0], TLS_RECORD_APPLICATION);
    assert_eq!(&record[1..3], &TLS_VERSION);
    assert_eq!(&record[3..5], &0u16.to_be_bytes());
}

#[test]
fn wrap_tls_application_record_oversized_payload_is_chunked_without_truncation() {
    let total = (u16::MAX as usize) + 37;
    let payload = vec![0xA5u8; total];
    let record = wrap_tls_application_record(&payload);

    let mut offset = 0usize;
    let mut recovered = Vec::with_capacity(total);
    let mut frames = 0usize;

    while offset + 5 <= record.len() {
        assert_eq!(record[offset], TLS_RECORD_APPLICATION);
        assert_eq!(&record[offset + 1..offset + 3], &TLS_VERSION);
        let len = u16::from_be_bytes([record[offset + 3], record[offset + 4]]) as usize;
        let body_start = offset + 5;
        let body_end = body_start + len;
        assert!(body_end <= record.len(), "declared TLS record length must be in-bounds");
        recovered.extend_from_slice(&record[body_start..body_end]);
        offset = body_end;
        frames += 1;
    }

    assert_eq!(offset, record.len(), "record parser must consume exact output size");
    assert_eq!(frames, 2, "oversized payload should split into exactly two records");
    assert_eq!(recovered, payload, "chunked records must preserve full payload");
}
