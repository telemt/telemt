use super::*;

fn handshake_source() -> &'static str {
    include_str!("../handshake.rs")
}

#[test]
fn security_dec_key_derivation_is_zeroized_in_candidate_loop() {
    let src = handshake_source();
    assert!(
        src.contains("let dec_key = Zeroizing::new(sha256(&dec_key_input));"),
        "candidate-loop dec_key derivation must be wrapped in Zeroizing to clear secrets on early-continue paths"
    );
}

#[test]
fn security_enc_key_derivation_is_zeroized_in_candidate_loop() {
    let src = handshake_source();
    assert!(
        src.contains("let enc_key = Zeroizing::new(sha256(&enc_key_input));"),
        "candidate-loop enc_key derivation must be wrapped in Zeroizing to clear secrets on early-continue paths"
    );
}

#[test]
fn security_aes_ctr_initialization_uses_zeroizing_references() {
    let src = handshake_source();
    assert!(
        src.contains("let mut decryptor = AesCtr::new(&dec_key, dec_iv);")
            && src.contains("let encryptor = AesCtr::new(&enc_key, enc_iv);"),
        "AES-CTR initialization must use Zeroizing key wrappers directly without creating extra plain key variables"
    );
}

#[test]
fn security_success_struct_copies_out_of_zeroizing_wrappers() {
    let src = handshake_source();
    assert!(
        src.contains("dec_key: *dec_key,") && src.contains("enc_key: *enc_key,"),
        "HandshakeSuccess construction must copy from Zeroizing wrappers so loop-local key material is dropped and zeroized"
    );
}
