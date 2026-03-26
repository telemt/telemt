use super::*;
use crate::protocol::constants::MAX_TLS_PLAINTEXT_SIZE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn handshake_record_above_plaintext_limit_must_be_rejected_early() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_HANDSHAKE,
        version: TLS_VERSION,
        length: (MAX_TLS_PLAINTEXT_SIZE + 1) as u16,
    };

    assert!(
        header.validate().is_err(),
        "control-plane handshake record > MAX_TLS_PLAINTEXT_SIZE must fail closed"
    );
}

#[test]
fn alert_record_above_plaintext_limit_must_be_rejected_early() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_ALERT,
        version: TLS_VERSION,
        length: (MAX_TLS_PLAINTEXT_SIZE + 1) as u16,
    };

    assert!(
        header.validate().is_err(),
        "TLS alert record > MAX_TLS_PLAINTEXT_SIZE must be rejected"
    );
}

#[test]
fn ccs_record_len_not_equal_one_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_CHANGE_CIPHER,
        version: TLS_VERSION,
        length: 2,
    };

    assert!(
        header.validate().is_err(),
        "ChangeCipherSpec length must be exactly 1 byte in compat mode"
    );
}

#[test]
fn handshake_record_len_zero_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_HANDSHAKE,
        version: TLS_VERSION,
        length: 0,
    };

    assert!(
        header.validate().is_err(),
        "zero-length handshake record is structurally invalid"
    );
}

#[test]
fn handshake_record_len_one_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_HANDSHAKE,
        version: TLS_VERSION,
        length: 1,
    };

    assert!(
        header.validate().is_err(),
        "tiny handshake record must be rejected to avoid malformed parser states"
    );
}

#[test]
fn handshake_record_len_four_is_accepted() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_HANDSHAKE,
        version: TLS_VERSION,
        length: 4,
    };

    assert!(
        header.validate().is_ok(),
        "4-byte handshake payload is the minimum carrying handshake header"
    );
}

#[test]
fn handshake_record_at_plaintext_limit_is_accepted() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_HANDSHAKE,
        version: TLS_VERSION,
        length: MAX_TLS_PLAINTEXT_SIZE as u16,
    };

    assert!(
        header.validate().is_ok(),
        "handshake record at plaintext RFC limit must be accepted"
    );
}

#[test]
fn handshake_record_at_ciphertext_limit_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_HANDSHAKE,
        version: TLS_VERSION,
        length: MAX_TLS_CIPHERTEXT_SIZE as u16,
    };

    assert!(
        header.validate().is_err(),
        "control-plane handshake must never use ciphertext upper bound"
    );
}

#[test]
fn alert_record_len_zero_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_ALERT,
        version: TLS_VERSION,
        length: 0,
    };

    assert!(
        header.validate().is_err(),
        "TLS alert must always carry level+description bytes"
    );
}

#[test]
fn alert_record_len_one_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_ALERT,
        version: TLS_VERSION,
        length: 1,
    };

    assert!(
        header.validate().is_err(),
        "one-byte TLS alert is malformed and must fail closed"
    );
}

#[test]
fn alert_record_len_two_is_accepted() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_ALERT,
        version: TLS_VERSION,
        length: 2,
    };

    assert!(
        header.validate().is_ok(),
        "standard TLS alert shape should be accepted"
    );
}

#[test]
fn alert_record_len_three_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_ALERT,
        version: TLS_VERSION,
        length: 3,
    };

    assert!(
        header.validate().is_err(),
        "oversized plaintext alert should be rejected to avoid parser confusion"
    );
}

#[test]
fn ccs_record_len_zero_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_CHANGE_CIPHER,
        version: TLS_VERSION,
        length: 0,
    };

    assert!(
        header.validate().is_err(),
        "ChangeCipherSpec with zero length is malformed"
    );
}

#[test]
fn ccs_record_len_one_is_accepted() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_CHANGE_CIPHER,
        version: TLS_VERSION,
        length: 1,
    };

    assert!(
        header.validate().is_ok(),
        "ChangeCipherSpec compat record length must be accepted only for len=1"
    );
}

#[test]
fn ccs_record_len_at_plaintext_limit_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_CHANGE_CIPHER,
        version: TLS_VERSION,
        length: MAX_TLS_PLAINTEXT_SIZE as u16,
    };

    assert!(
        header.validate().is_err(),
        "oversized CCS control frame must fail closed"
    );
}

#[test]
fn unknown_record_type_small_len_must_be_rejected_early() {
    let header = TlsRecordHeader {
        record_type: 0x19,
        version: TLS_VERSION,
        length: 8,
    };

    assert!(
        header.validate().is_err(),
        "unknown TLS record type should be rejected during header validation"
    );
}

#[test]
fn unknown_record_type_large_len_must_be_rejected_early() {
    let header = TlsRecordHeader {
        record_type: 0x7f,
        version: TLS_VERSION,
        length: MAX_TLS_CIPHERTEXT_SIZE as u16,
    };

    assert!(
        header.validate().is_err(),
        "unknown record type with large payload must fail before body allocation"
    );
}

#[test]
fn handshake_tls10_header_with_plaintext_plus_one_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_HANDSHAKE,
        version: [0x03, 0x01],
        length: (MAX_TLS_PLAINTEXT_SIZE + 1) as u16,
    };

    assert!(
        header.validate().is_err(),
        "TLS 1.0 compatibility header must not bypass plaintext size cap"
    );
}

#[test]
fn alert_tls10_header_with_invalid_len_must_be_rejected() {
    let header = TlsRecordHeader {
        record_type: TLS_RECORD_ALERT,
        version: [0x03, 0x01],
        length: 3,
    };

    assert!(
        header.validate().is_err(),
        "TLS 1.0 compatibility header must not bypass strict alert framing"
    );
}

fn validates(record_type: u8, version: [u8; 2], length: u16) -> bool {
    TlsRecordHeader {
        record_type,
        version,
        length,
    }
    .validate()
    .is_ok()
}

macro_rules! expect_reject {
    ($name:ident, $record_type:expr, $version:expr, $length:expr) => {
        #[test]
        fn $name() {
            assert!(
                !validates($record_type, $version, $length),
                "expected reject for type=0x{:02x} version={:02x?} len={}",
                $record_type,
                $version,
                $length
            );
        }
    };
}

macro_rules! expect_accept {
    ($name:ident, $record_type:expr, $version:expr, $length:expr) => {
        #[test]
        fn $name() {
            assert!(
                validates($record_type, $version, $length),
                "expected accept for type=0x{:02x} version={:02x?} len={}",
                $record_type,
                $version,
                $length
            );
        }
    };
}

expect_reject!(
    appdata_zero_len_must_be_rejected,
    TLS_RECORD_APPLICATION,
    TLS_VERSION,
    0
);
expect_accept!(
    appdata_one_len_is_accepted,
    TLS_RECORD_APPLICATION,
    TLS_VERSION,
    1
);
expect_accept!(
    appdata_small_len_is_accepted,
    TLS_RECORD_APPLICATION,
    TLS_VERSION,
    32
);
expect_accept!(
    appdata_medium_len_is_accepted,
    TLS_RECORD_APPLICATION,
    TLS_VERSION,
    1024
);
expect_accept!(
    appdata_plaintext_limit_is_accepted,
    TLS_RECORD_APPLICATION,
    TLS_VERSION,
    MAX_TLS_PLAINTEXT_SIZE as u16
);
expect_accept!(
    appdata_ciphertext_limit_is_accepted,
    TLS_RECORD_APPLICATION,
    TLS_VERSION,
    MAX_TLS_CIPHERTEXT_SIZE as u16
);
expect_reject!(
    appdata_ciphertext_plus_one_must_be_rejected,
    TLS_RECORD_APPLICATION,
    TLS_VERSION,
    (MAX_TLS_CIPHERTEXT_SIZE as u16) + 1
);

expect_reject!(
    appdata_tls10_header_len_one_must_be_rejected,
    TLS_RECORD_APPLICATION,
    [0x03, 0x01],
    1
);
expect_reject!(
    appdata_tls10_header_medium_must_be_rejected,
    TLS_RECORD_APPLICATION,
    [0x03, 0x01],
    1024
);
expect_reject!(
    appdata_tls10_header_ciphertext_limit_must_be_rejected,
    TLS_RECORD_APPLICATION,
    [0x03, 0x01],
    MAX_TLS_CIPHERTEXT_SIZE as u16
);

expect_reject!(
    ccs_tls10_header_len_one_must_be_rejected,
    TLS_RECORD_CHANGE_CIPHER,
    [0x03, 0x01],
    1
);
expect_reject!(
    ccs_tls10_header_len_zero_must_be_rejected,
    TLS_RECORD_CHANGE_CIPHER,
    [0x03, 0x01],
    0
);
expect_reject!(
    ccs_tls10_header_len_two_must_be_rejected,
    TLS_RECORD_CHANGE_CIPHER,
    [0x03, 0x01],
    2
);

expect_reject!(
    alert_tls10_header_len_two_must_be_rejected,
    TLS_RECORD_ALERT,
    [0x03, 0x01],
    2
);
expect_reject!(
    alert_tls10_header_len_one_must_be_rejected,
    TLS_RECORD_ALERT,
    [0x03, 0x01],
    1
);
expect_reject!(
    alert_tls10_header_len_three_must_be_rejected,
    TLS_RECORD_ALERT,
    [0x03, 0x01],
    3
);

expect_accept!(
    handshake_tls10_header_min_len_is_accepted,
    TLS_RECORD_HANDSHAKE,
    [0x03, 0x01],
    4
);
expect_accept!(
    handshake_tls10_header_plaintext_limit_is_accepted,
    TLS_RECORD_HANDSHAKE,
    [0x03, 0x01],
    MAX_TLS_PLAINTEXT_SIZE as u16
);
expect_reject!(
    handshake_tls10_header_too_small_must_be_rejected,
    TLS_RECORD_HANDSHAKE,
    [0x03, 0x01],
    3
);
expect_reject!(
    handshake_tls10_header_too_large_must_be_rejected,
    TLS_RECORD_HANDSHAKE,
    [0x03, 0x01],
    (MAX_TLS_PLAINTEXT_SIZE as u16) + 1
);

expect_reject!(
    unknown_type_tls13_zero_must_be_rejected,
    0x00,
    TLS_VERSION,
    0
);
expect_reject!(
    unknown_type_tls13_small_must_be_rejected,
    0x13,
    TLS_VERSION,
    32
);
expect_reject!(
    unknown_type_tls13_large_must_be_rejected,
    0xfe,
    TLS_VERSION,
    MAX_TLS_CIPHERTEXT_SIZE as u16
);
expect_reject!(
    unknown_type_tls10_small_must_be_rejected,
    0x13,
    [0x03, 0x01],
    32
);

expect_reject!(
    appdata_invalid_version_0302_must_be_rejected,
    TLS_RECORD_APPLICATION,
    [0x03, 0x02],
    128
);
expect_reject!(
    handshake_invalid_version_0302_must_be_rejected,
    TLS_RECORD_HANDSHAKE,
    [0x03, 0x02],
    128
);
expect_reject!(
    alert_invalid_version_0302_must_be_rejected,
    TLS_RECORD_ALERT,
    [0x03, 0x02],
    2
);
expect_reject!(
    ccs_invalid_version_0302_must_be_rejected,
    TLS_RECORD_CHANGE_CIPHER,
    [0x03, 0x02],
    1
);

expect_reject!(
    appdata_invalid_version_0304_must_be_rejected,
    TLS_RECORD_APPLICATION,
    [0x03, 0x04],
    128
);
expect_reject!(
    handshake_invalid_version_0304_must_be_rejected,
    TLS_RECORD_HANDSHAKE,
    [0x03, 0x04],
    128
);
expect_reject!(
    alert_invalid_version_0304_must_be_rejected,
    TLS_RECORD_ALERT,
    [0x03, 0x04],
    2
);
expect_reject!(
    ccs_invalid_version_0304_must_be_rejected,
    TLS_RECORD_CHANGE_CIPHER,
    [0x03, 0x04],
    1
);

expect_accept!(
    handshake_tls13_len_5_is_accepted,
    TLS_RECORD_HANDSHAKE,
    TLS_VERSION,
    5
);
expect_accept!(
    appdata_tls13_len_16385_is_accepted,
    TLS_RECORD_APPLICATION,
    TLS_VERSION,
    (MAX_TLS_PLAINTEXT_SIZE as u16) + 1
);

#[test]
fn matrix_version_policy_is_strict_and_deterministic() {
    let versions = [
        [0x03, 0x01],
        TLS_VERSION,
        [0x03, 0x02],
        [0x03, 0x04],
        [0x00, 0x00],
    ];
    let record_types = [
        TLS_RECORD_APPLICATION,
        TLS_RECORD_CHANGE_CIPHER,
        TLS_RECORD_ALERT,
        TLS_RECORD_HANDSHAKE,
    ];

    for version in versions {
        for record_type in record_types {
            let len = match record_type {
                TLS_RECORD_APPLICATION => 1,
                TLS_RECORD_CHANGE_CIPHER => 1,
                TLS_RECORD_ALERT => 2,
                TLS_RECORD_HANDSHAKE => 4,
                _ => unreachable!(),
            };

            let accepted = validates(record_type, version, len);
            let expected = if version == TLS_VERSION {
                true
            } else {
                version == [0x03, 0x01] && record_type == TLS_RECORD_HANDSHAKE
            };

            assert_eq!(
                accepted, expected,
                "version policy mismatch for type=0x{:02x} version={:02x?}",
                record_type, version
            );
        }
    }
}

#[test]
fn appdata_partition_property_holds_for_all_u16_edges() {
    for len in [
        0u16,
        1,
        2,
        3,
        64,
        255,
        1024,
        4096,
        8192,
        16_384,
        16_385,
        16_640,
        16_641,
        u16::MAX,
    ] {
        let accepted = validates(TLS_RECORD_APPLICATION, TLS_VERSION, len);
        let expected = len >= 1 && usize::from(len) <= MAX_TLS_CIPHERTEXT_SIZE;
        assert_eq!(
            accepted, expected,
            "unexpected appdata decision for len={len}"
        );
    }
}

#[test]
fn handshake_partition_property_holds_for_all_u16_edges() {
    for len in [
        0u16,
        1,
        2,
        3,
        4,
        5,
        64,
        255,
        1024,
        4096,
        8192,
        16_383,
        16_384,
        16_385,
        u16::MAX,
    ] {
        let accepted_tls13 = validates(TLS_RECORD_HANDSHAKE, TLS_VERSION, len);
        let accepted_tls10 = validates(TLS_RECORD_HANDSHAKE, [0x03, 0x01], len);
        let expected = (4..=MAX_TLS_PLAINTEXT_SIZE).contains(&usize::from(len));

        assert_eq!(
            accepted_tls13, expected,
            "TLS1.3 handshake mismatch for len={len}"
        );
        assert_eq!(
            accepted_tls10, expected,
            "TLS1.0 compat handshake mismatch for len={len}"
        );
    }
}

#[test]
fn control_record_exact_lengths_are_enforced_under_fuzzed_lengths() {
    let mut x: u32 = 0xC0FFEE11;
    for _ in 0..5000 {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        let len = (x & 0xFFFF) as u16;

        let ccs_ok = validates(TLS_RECORD_CHANGE_CIPHER, TLS_VERSION, len);
        let alert_ok = validates(TLS_RECORD_ALERT, TLS_VERSION, len);

        assert_eq!(ccs_ok, len == 1, "ccs length gate mismatch for len={len}");
        assert_eq!(
            alert_ok,
            len == 2,
            "alert length gate mismatch for len={len}"
        );
    }
}

#[test]
fn unknown_record_types_never_validate_under_supported_versions() {
    for record_type in 0u8..=255 {
        if matches!(
            record_type,
            TLS_RECORD_APPLICATION
                | TLS_RECORD_CHANGE_CIPHER
                | TLS_RECORD_ALERT
                | TLS_RECORD_HANDSHAKE
        ) {
            continue;
        }

        assert!(
            !validates(record_type, TLS_VERSION, 1),
            "unknown type must not validate under TLS_VERSION: 0x{record_type:02x}"
        );
        assert!(
            !validates(record_type, [0x03, 0x01], 4),
            "unknown type must not validate under TLS1.0 compat: 0x{record_type:02x}"
        );
    }
}

#[tokio::test]
async fn reader_rejects_tls10_appdata_header_before_payload_processing() {
    let (mut tx, rx) = tokio::io::duplex(128);
    tx.write_all(&[TLS_RECORD_APPLICATION, 0x03, 0x01, 0x00, 0x01, 0xAB])
        .await
        .unwrap();
    tx.shutdown().await.unwrap();

    let mut reader = FakeTlsReader::new(rx);
    let mut out = [0u8; 1];
    let err = reader.read(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn reader_rejects_zero_len_appdata_record() {
    let (mut tx, rx) = tokio::io::duplex(128);
    tx.write_all(&[
        TLS_RECORD_APPLICATION,
        TLS_VERSION[0],
        TLS_VERSION[1],
        0x00,
        0x00,
    ])
    .await
    .unwrap();
    tx.shutdown().await.unwrap();

    let mut reader = FakeTlsReader::new(rx);
    let mut out = [0u8; 1];
    let err = reader.read(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn reader_accepts_single_byte_tls13_appdata_and_yields_payload() {
    let (mut tx, rx) = tokio::io::duplex(128);
    tx.write_all(&[
        TLS_RECORD_APPLICATION,
        TLS_VERSION[0],
        TLS_VERSION[1],
        0x00,
        0x01,
        0x5A,
    ])
    .await
    .unwrap();
    tx.shutdown().await.unwrap();

    let mut reader = FakeTlsReader::new(rx);
    let mut out = [0u8; 1];
    let n = reader.read(&mut out).await.unwrap();
    assert_eq!(n, 1);
    assert_eq!(out[0], 0x5A);
}

#[tokio::test]
async fn reader_rejects_tls10_alert_even_with_structural_length() {
    let (mut tx, rx) = tokio::io::duplex(128);
    tx.write_all(&[TLS_RECORD_ALERT, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28])
        .await
        .unwrap();
    tx.shutdown().await.unwrap();

    let mut reader = FakeTlsReader::new(rx);
    let mut out = [0u8; 8];
    let err = reader.read(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn reader_rejects_unknown_record_type_fast() {
    let (mut tx, rx) = tokio::io::duplex(128);
    tx.write_all(&[0x7f, TLS_VERSION[0], TLS_VERSION[1], 0x00, 0x01, 0x01])
        .await
        .unwrap();
    tx.shutdown().await.unwrap();

    let mut reader = FakeTlsReader::new(rx);
    let mut out = [0u8; 8];
    let err = reader.read(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn reader_preserves_data_after_valid_ccs_then_valid_appdata() {
    let (mut tx, rx) = tokio::io::duplex(256);
    tx.write_all(&[
        TLS_RECORD_CHANGE_CIPHER,
        TLS_VERSION[0],
        TLS_VERSION[1],
        0x00,
        0x01,
        0x01,
        TLS_RECORD_APPLICATION,
        TLS_VERSION[0],
        TLS_VERSION[1],
        0x00,
        0x03,
        0xDE,
        0xAD,
        0xBE,
    ])
    .await
    .unwrap();
    tx.shutdown().await.unwrap();

    let mut reader = FakeTlsReader::new(rx);
    let mut out = [0u8; 3];
    let n = reader.read(&mut out).await.unwrap();
    assert_eq!(n, 3);
    assert_eq!(out, [0xDE, 0xAD, 0xBE]);
}

#[test]
fn deterministic_lcg_never_breaks_validation_invariants() {
    let mut x: u64 = 0xD1A5_CE55_0BAD_F00D;
    for _ in 0..20000 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        let record_type = (x & 0xFF) as u8;
        let version = match (x >> 8) & 0x3 {
            0 => TLS_VERSION,
            1 => [0x03, 0x01],
            2 => [0x03, 0x02],
            _ => [0x03, 0x04],
        };
        let len = ((x >> 16) & 0xFFFF) as u16;

        let accepted = validates(record_type, version, len);

        let expected = match record_type {
            TLS_RECORD_APPLICATION => {
                version == TLS_VERSION && len >= 1 && usize::from(len) <= MAX_TLS_CIPHERTEXT_SIZE
            }
            TLS_RECORD_CHANGE_CIPHER => version == TLS_VERSION && len == 1,
            TLS_RECORD_ALERT => version == TLS_VERSION && len == 2,
            TLS_RECORD_HANDSHAKE => {
                (version == TLS_VERSION || version == [0x03, 0x01])
                    && (4..=MAX_TLS_PLAINTEXT_SIZE).contains(&usize::from(len))
            }
            _ => false,
        };

        assert_eq!(
            accepted, expected,
            "invariant mismatch: type=0x{record_type:02x} version={version:02x?} len={len}"
        );
    }
}
