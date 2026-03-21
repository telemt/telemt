use super::*;

#[test]
fn extension_builder_fails_closed_on_u16_length_overflow() {
    let builder = TlsExtensionBuilder {
        extensions: vec![0u8; (u16::MAX as usize) + 1],
    };

    let built = builder.build();
    assert!(
        built.is_empty(),
        "oversized extension blob must fail closed instead of truncating length field"
    );
}

#[test]
fn server_hello_builder_fails_closed_on_session_id_len_overflow() {
    let builder = ServerHelloBuilder {
        random: [0u8; 32],
        session_id: vec![0xAB; (u8::MAX as usize) + 1],
        cipher_suite: cipher_suite::TLS_AES_128_GCM_SHA256,
        compression: 0,
        extensions: TlsExtensionBuilder::new(),
    };

    let message = builder.build_message();
    let record = builder.build_record();

    assert!(
        message.is_empty(),
        "session_id length overflow must fail closed in message builder"
    );
    assert!(
        record.is_empty(),
        "session_id length overflow must fail closed in record builder"
    );
}
