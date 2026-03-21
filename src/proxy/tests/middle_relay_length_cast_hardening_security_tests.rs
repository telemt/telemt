use super::*;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

#[test]
fn intermediate_secure_wire_len_allows_max_31bit_payload() {
    let (len_val, total) = compute_intermediate_secure_wire_len(0x7fff_fffe, 1, true)
        .expect("31-bit wire length should be accepted");

    assert_eq!(len_val, 0xffff_ffff, "quickack must use top bit only");
    assert_eq!(total, 0x8000_0003);
}

#[test]
fn intermediate_secure_wire_len_rejects_length_above_31bit_limit() {
    let err = compute_intermediate_secure_wire_len(0x7fff_ffff, 1, false)
        .expect_err("wire length above 31-bit must fail closed");
    assert!(
        format!("{err}").contains("frame too large"),
        "error should identify oversize frame path"
    );
}

#[test]
fn intermediate_secure_wire_len_rejects_addition_overflow() {
    let err = compute_intermediate_secure_wire_len(usize::MAX, 1, false)
        .expect_err("overflowing addition must fail closed");
    assert!(
        format!("{err}").contains("overflow"),
        "error should clearly report overflow"
    );
}

#[test]
fn desync_forensics_len_bytes_marks_truncation_for_oversize_values() {
    let (small_bytes, small_truncated) = desync_forensics_len_bytes(0x1020_3040);
    assert_eq!(small_bytes, 0x1020_3040u32.to_le_bytes());
    assert!(!small_truncated);

    let (huge_bytes, huge_truncated) = desync_forensics_len_bytes(usize::MAX);
    assert_eq!(huge_bytes, u32::MAX.to_le_bytes());
    assert!(huge_truncated);
}

#[test]
fn report_desync_frame_too_large_preserves_full_length_in_error_message() {
    let state = RelayForensicsState {
        trace_id: 0x1234,
        conn_id: 0x5678,
        user: "middle-desync-oversize".to_string(),
        peer: "198.51.100.55:443".parse().expect("valid test peer"),
        peer_hash: 0xAABBCCDD,
        started_at: Instant::now(),
        bytes_c2me: 7,
        bytes_me2c: Arc::new(AtomicU64::new(9)),
        desync_all_full: false,
    };

    let huge_len = usize::MAX;
    let err = report_desync_frame_too_large(
        &state,
        ProtoTag::Intermediate,
        3,
        1024,
        huge_len,
        None,
        &Stats::new(),
    );

    let msg = format!("{err}");
    assert!(
        msg.contains(&huge_len.to_string()),
        "error must preserve full usize length for forensics"
    );
}
