fn old_padding_round_up_to_4(len: usize) -> Option<usize> {
    len.checked_add(3)
        .map(|sum| sum / 4)
        .and_then(|words| words.checked_mul(4))
}

fn new_padding_round_up_to_4(len: usize) -> Option<usize> {
    len.div_ceil(4).checked_mul(4)
}

#[test]
fn padding_rounding_equivalent_for_extensive_safe_domain() {
    for len in 0usize..=200_000usize {
        let old = old_padding_round_up_to_4(len).expect("old expression must be safe");
        let new = new_padding_round_up_to_4(len).expect("new expression must be safe");
        assert_eq!(old, new, "mismatch for len={len}");
        assert!(new >= len, "rounded length must not shrink: len={len}, out={new}");
        assert_eq!(new % 4, 0, "rounded length must stay 4-byte aligned");
    }
}

#[test]
fn padding_rounding_equivalent_near_usize_limit_when_old_is_defined() {
    let candidates = [
        usize::MAX - 3,
        usize::MAX - 4,
        usize::MAX - 5,
        usize::MAX - 6,
        usize::MAX - 7,
        usize::MAX - 8,
        usize::MAX - 15,
        usize::MAX / 2,
        (usize::MAX / 2) + 1,
    ];

    for len in candidates {
        let old = old_padding_round_up_to_4(len);
        let new = new_padding_round_up_to_4(len);
        if let Some(old_val) = old {
            assert_eq!(Some(old_val), new, "safe-domain mismatch for len={len}");
        }
    }
}

#[test]
fn padding_rounding_documents_overflow_boundary_behavior() {
    // For very large lengths, arithmetic round-up may overflow regardless of spelling.
    // This documents the boundary so future changes do not assume universal safety.
    assert_eq!(old_padding_round_up_to_4(usize::MAX), None);
    assert_eq!(old_padding_round_up_to_4(usize::MAX - 1), None);
    assert_eq!(old_padding_round_up_to_4(usize::MAX - 2), None);

    // The div_ceil form avoids `len + 3` overflow, but final `* 4` can still overflow.
    assert_eq!(new_padding_round_up_to_4(usize::MAX), None);
    assert_eq!(new_padding_round_up_to_4(usize::MAX - 1), None);
}
