use super::*;
use bytes::{Bytes, BytesMut};

#[test]
fn reading_body_pending_application_plaintext_is_preserved_on_into_inner() {
    let sample = b"coalesced-tail-after-mtproto";
    let mut reader = FakeTlsReader::new(tokio::io::empty());
    reader.state = TlsReaderState::ReadingBody {
        record_type: TLS_RECORD_APPLICATION,
        length: sample.len(),
        buffer: BytesMut::from(&sample[..]),
    };

    let (_inner, pending) = reader.into_inner_with_pending_plaintext();
    assert_eq!(
        pending,
        sample,
        "partial application-data body must survive into fallback path"
    );
}

#[test]
fn yielding_pending_plaintext_is_preserved_on_into_inner() {
    let sample = b"already-decoded-buffer";
    let mut reader = FakeTlsReader::new(tokio::io::empty());
    reader.state = TlsReaderState::Yielding {
        buffer: YieldBuffer::new(Bytes::copy_from_slice(sample)),
    };

    let (_inner, pending) = reader.into_inner_with_pending_plaintext();
    assert_eq!(pending, sample);
}

#[test]
fn reading_body_non_application_record_does_not_produce_plaintext() {
    let sample = b"unexpected-handshake-fragment";
    let mut reader = FakeTlsReader::new(tokio::io::empty());
    reader.state = TlsReaderState::ReadingBody {
        record_type: TLS_RECORD_HANDSHAKE,
        length: sample.len(),
        buffer: BytesMut::from(&sample[..]),
    };

    let (_inner, pending) = reader.into_inner_with_pending_plaintext();
    assert!(
        pending.is_empty(),
        "non-application partial body must not be surfaced as plaintext"
    );
}

#[test]
fn partial_header_state_does_not_produce_plaintext() {
    let mut header = HeaderBuffer::<TLS_HEADER_SIZE>::new();
    let unfilled = header.unfilled_mut();
    unfilled[0] = TLS_RECORD_APPLICATION;
    header.advance(1);

    let mut reader = FakeTlsReader::new(tokio::io::empty());
    reader.state = TlsReaderState::ReadingHeader { header };

    let (_inner, pending) = reader.into_inner_with_pending_plaintext();
    assert!(pending.is_empty(), "partial header bytes are not plaintext payload");
}

#[test]
fn edge_zero_length_application_fragment_remains_empty_without_panics() {
    let mut reader = FakeTlsReader::new(tokio::io::empty());
    reader.state = TlsReaderState::ReadingBody {
        record_type: TLS_RECORD_APPLICATION,
        length: 0,
        buffer: BytesMut::new(),
    };

    let (_inner, pending) = reader.into_inner_with_pending_plaintext();
    assert!(pending.is_empty());
}

#[test]
fn adversarial_poisoned_state_never_leaks_pending_bytes() {
    let mut reader = FakeTlsReader::new(tokio::io::empty());
    reader.state = TlsReaderState::Poisoned {
        error: Some(std::io::Error::other("poisoned by adversarial input")),
    };

    let (_inner, pending) = reader.into_inner_with_pending_plaintext();
    assert!(pending.is_empty(), "poisoned state must fail-closed for fallback payload");
}

#[test]
fn stress_large_application_fragment_survives_state_extraction() {
    let mut payload = vec![0u8; 96 * 1024];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17).wrapping_add(3);
    }

    let mut reader = FakeTlsReader::new(tokio::io::empty());
    reader.state = TlsReaderState::ReadingBody {
        record_type: TLS_RECORD_APPLICATION,
        length: payload.len(),
        buffer: BytesMut::from(&payload[..]),
    };

    let (_inner, pending) = reader.into_inner_with_pending_plaintext();
    assert_eq!(pending, payload, "large pending application plaintext must be preserved exactly");
}

#[test]
fn light_fuzz_state_matrix_preserves_pending_contract() {
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;

    for _ in 0..4096 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let len = (seed & 0x1ff) as usize;
        let mut payload = vec![0u8; len];
        for (idx, b) in payload.iter_mut().enumerate() {
            *b = (seed as u8).wrapping_add(idx as u8);
        }

        let record_type = match seed & 0x3 {
            0 => TLS_RECORD_APPLICATION,
            1 => TLS_RECORD_HANDSHAKE,
            2 => TLS_RECORD_ALERT,
            _ => TLS_RECORD_CHANGE_CIPHER,
        };

        let mut reader = FakeTlsReader::new(tokio::io::empty());
        reader.state = TlsReaderState::ReadingBody {
            record_type,
            length: payload.len(),
            buffer: BytesMut::from(&payload[..]),
        };

        let (_inner, pending) = reader.into_inner_with_pending_plaintext();
        if record_type == TLS_RECORD_APPLICATION {
            assert_eq!(pending, payload);
        } else {
            assert!(pending.is_empty());
        }
    }
}
