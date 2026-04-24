#![allow(clippy::too_many_arguments)]

use crate::crypto::{SecureRandom, sha256_hmac};
use crate::protocol::constants::{
    MAX_TLS_CIPHERTEXT_SIZE, TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER,
    TLS_RECORD_HANDSHAKE, TLS_VERSION,
};
use crate::protocol::tls::{
    ClientHelloTlsVersion, TLS_DIGEST_LEN, TLS_DIGEST_POS, gen_fake_x25519_key,
};
use crate::tls_front::types::{CachedTlsData, ParsedCertificateInfo, TlsProfileSource};
use crc32fast::Hasher;

const MIN_APP_DATA: usize = 64;
const MAX_APP_DATA: usize = MAX_TLS_CIPHERTEXT_SIZE;
const MAX_TICKET_RECORDS: usize = 4;

fn jitter_and_clamp_sizes(sizes: &[usize], rng: &SecureRandom) -> Vec<usize> {
    sizes
        .iter()
        .map(|&size| {
            let base = size.clamp(MIN_APP_DATA, MAX_APP_DATA);
            let jitter_range = ((base as f64) * 0.03).round() as i64;
            if jitter_range == 0 {
                return base;
            }
            let mut rand_bytes = [0u8; 2];
            rand_bytes.copy_from_slice(&rng.bytes(2));
            let span = 2 * jitter_range + 1;
            let delta = (u16::from_le_bytes(rand_bytes) as i64 % span) - jitter_range;
            let adjusted = (base as i64 + delta).clamp(MIN_APP_DATA as i64, MAX_APP_DATA as i64);
            adjusted as usize
        })
        .collect()
}

fn app_data_body_capacity(sizes: &[usize]) -> usize {
    sizes.iter().map(|&size| size.saturating_sub(17)).sum()
}

fn ensure_payload_capacity(mut sizes: Vec<usize>, payload_len: usize) -> Vec<usize> {
    if payload_len == 0 {
        return sizes;
    }

    let mut body_total = app_data_body_capacity(&sizes);
    if body_total >= payload_len {
        return sizes;
    }

    if let Some(last) = sizes.last_mut() {
        let free = MAX_APP_DATA.saturating_sub(*last);
        let grow = free.min(payload_len - body_total);
        *last += grow;
        body_total += grow;
    }

    while body_total < payload_len {
        let remaining = payload_len - body_total;
        let chunk = (remaining + 17).clamp(MIN_APP_DATA, MAX_APP_DATA);
        sizes.push(chunk);
        body_total += chunk.saturating_sub(17);
    }

    sizes
}

fn emulated_app_data_sizes(cached: &CachedTlsData) -> Vec<usize> {
    match cached.behavior_profile.source {
        TlsProfileSource::Raw | TlsProfileSource::Merged => {
            return cached
                .app_data_records_sizes
                .first()
                .copied()
                .or_else(|| {
                    cached
                        .behavior_profile
                        .app_data_record_sizes
                        .first()
                        .copied()
                })
                .map(|size| vec![size])
                .unwrap_or_else(|| vec![cached.total_app_data_len.max(1024)]);
        }
        TlsProfileSource::Default | TlsProfileSource::Rustls => {}
    }

    let mut sizes = cached.app_data_records_sizes.clone();
    if sizes.is_empty() {
        sizes.push(cached.total_app_data_len.max(1024));
    }
    sizes
}

fn emulated_change_cipher_spec_count(_cached: &CachedTlsData) -> usize {
    1
}

fn emulated_ticket_record_sizes(
    cached: &CachedTlsData,
    new_session_tickets: u8,
    rng: &SecureRandom,
) -> Vec<usize> {
    let target_count = usize::from(new_session_tickets.min(MAX_TICKET_RECORDS as u8));
    if target_count == 0 {
        return Vec::new();
    }

    let profiled_sizes = match cached.behavior_profile.source {
        TlsProfileSource::Raw | TlsProfileSource::Merged => {
            cached.behavior_profile.ticket_record_sizes.as_slice()
        }
        TlsProfileSource::Default | TlsProfileSource::Rustls => &[],
    };

    let mut sizes = Vec::with_capacity(target_count);
    sizes.extend(profiled_sizes.iter().copied().take(target_count));

    while sizes.len() < target_count {
        sizes.push(rng.range(48) + 48);
    }

    sizes
}

fn build_compact_cert_info_payload(cert_info: &ParsedCertificateInfo) -> Option<Vec<u8>> {
    let mut fields = Vec::new();

    if let Some(subject) = cert_info.subject_cn.as_deref() {
        fields.push(format!("CN={subject}"));
    }
    if let Some(issuer) = cert_info.issuer_cn.as_deref() {
        fields.push(format!("ISSUER={issuer}"));
    }
    if let Some(not_before) = cert_info.not_before_unix {
        fields.push(format!("NB={not_before}"));
    }
    if let Some(not_after) = cert_info.not_after_unix {
        fields.push(format!("NA={not_after}"));
    }
    if !cert_info.san_names.is_empty() {
        let san = cert_info
            .san_names
            .iter()
            .take(8)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",");
        fields.push(format!("SAN={san}"));
    }

    if fields.is_empty() {
        return None;
    }

    let mut payload = fields.join(";").into_bytes();
    if payload.len() > 512 {
        payload.truncate(512);
    }
    Some(payload)
}

fn hash_compact_cert_info_payload(cert_payload: Vec<u8>) -> Option<Vec<u8>> {
    if cert_payload.is_empty() {
        return None;
    }

    let mut hashed = Vec::with_capacity(cert_payload.len());
    let mut seed_hasher = Hasher::new();
    seed_hasher.update(&cert_payload);
    let mut state = seed_hasher.finalize();

    while hashed.len() < cert_payload.len() {
        let mut hasher = Hasher::new();
        hasher.update(&state.to_le_bytes());
        hasher.update(&cert_payload);
        state = hasher.finalize();

        let block = state.to_le_bytes();
        let remaining = cert_payload.len() - hashed.len();
        let copy_len = remaining.min(block.len());
        hashed.extend_from_slice(&block[..copy_len]);
    }

    Some(hashed)
}

/// Build a ServerHello + CCS + ApplicationData sequence using cached TLS metadata.
pub fn build_emulated_server_hello(
    secret: &[u8],
    client_digest: &[u8; TLS_DIGEST_LEN],
    session_id: &[u8],
    cached: &CachedTlsData,
    use_full_cert_payload: bool,
    serverhello_compact: bool,
    client_tls_version: ClientHelloTlsVersion,
    rng: &SecureRandom,
    alpn: Option<Vec<u8>>,
    new_session_tickets: u8,
) -> Vec<u8> {
    // --- ServerHello ---
    let mut extensions = Vec::new();
    let key = gen_fake_x25519_key(rng);
    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&(2 + 2 + 32u16).to_be_bytes());
    extensions.extend_from_slice(&0x001du16.to_be_bytes());
    extensions.extend_from_slice(&(32u16).to_be_bytes());
    extensions.extend_from_slice(&key);
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&(2u16).to_be_bytes());
    extensions.extend_from_slice(&0x0304u16.to_be_bytes());
    let extensions_len = extensions.len() as u16;

    let body_len = 2 + // version
        32 + // random
        1 + session_id.len() + // session id
        2 + // cipher
        1 + // compression
        2 + extensions.len(); // extensions

    let mut message = Vec::with_capacity(4 + body_len);
    message.push(0x02); // ServerHello
    let len_bytes = (body_len as u32).to_be_bytes();
    message.extend_from_slice(&len_bytes[1..4]);
    message.extend_from_slice(&cached.server_hello_template.version); // 0x0303
    message.extend_from_slice(&[0u8; 32]); // random placeholder
    message.push(session_id.len() as u8);
    message.extend_from_slice(session_id);
    let cipher = if cached.server_hello_template.cipher_suite == [0, 0] {
        [0x13, 0x01]
    } else {
        cached.server_hello_template.cipher_suite
    };
    message.extend_from_slice(&cipher);
    message.push(cached.server_hello_template.compression);
    message.extend_from_slice(&extensions_len.to_be_bytes());
    message.extend_from_slice(&extensions);

    let mut server_hello = Vec::with_capacity(5 + message.len());
    server_hello.push(TLS_RECORD_HANDSHAKE);
    server_hello.extend_from_slice(&TLS_VERSION);
    server_hello.extend_from_slice(&(message.len() as u16).to_be_bytes());
    server_hello.extend_from_slice(&message);

    // --- ChangeCipherSpec ---
    let change_cipher_spec_count = emulated_change_cipher_spec_count(cached);
    let mut change_cipher_spec = Vec::with_capacity(change_cipher_spec_count * 6);
    for _ in 0..change_cipher_spec_count {
        change_cipher_spec.extend_from_slice(&[
            TLS_RECORD_CHANGE_CIPHER,
            TLS_VERSION[0],
            TLS_VERSION[1],
            0x00,
            0x01,
            0x01,
        ]);
    }

    // --- ApplicationData (fake encrypted records) ---
    let mut sizes = {
        let base_sizes = emulated_app_data_sizes(cached);
        match cached.behavior_profile.source {
            TlsProfileSource::Raw | TlsProfileSource::Merged => base_sizes
                .into_iter()
                .map(|size| size.clamp(MIN_APP_DATA, MAX_APP_DATA))
                .collect(),
            TlsProfileSource::Default | TlsProfileSource::Rustls => {
                jitter_and_clamp_sizes(&base_sizes, rng)
            }
        }
    };
    let compact_payload = if serverhello_compact {
        cached
            .cert_info
            .as_ref()
            .and_then(build_compact_cert_info_payload)
            .and_then(hash_compact_cert_info_payload)
    } else {
        None
    };
    let full_payload = cached
        .cert_payload
        .as_ref()
        .map(|payload| payload.certificate_message.as_slice())
        .filter(|payload| !payload.is_empty());
    let selected_payload: Option<&[u8]> = match client_tls_version {
        ClientHelloTlsVersion::Tls13 => None,
        ClientHelloTlsVersion::Tls12 => {
            if serverhello_compact {
                if use_full_cert_payload {
                    full_payload.or(compact_payload.as_deref())
                } else {
                    compact_payload.as_deref()
                }
            } else {
                full_payload
            }
        }
    };

    if let Some(payload) = selected_payload {
        sizes = ensure_payload_capacity(sizes, payload.len());
    }

    let mut app_data = Vec::new();
    let alpn_marker = alpn
        .as_ref()
        .filter(|p| !p.is_empty() && p.len() <= u8::MAX as usize)
        .map(|proto| {
            let proto_list_len = 1usize + proto.len();
            let ext_data_len = 2usize + proto_list_len;
            let mut marker = Vec::with_capacity(4 + ext_data_len);
            marker.extend_from_slice(&0x0010u16.to_be_bytes());
            marker.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
            marker.extend_from_slice(&(proto_list_len as u16).to_be_bytes());
            marker.push(proto.len() as u8);
            marker.extend_from_slice(proto);
            marker
        });
    for (idx, size) in sizes.into_iter().enumerate() {
        let mut rec = Vec::with_capacity(5 + size);
        rec.push(TLS_RECORD_APPLICATION);
        rec.extend_from_slice(&TLS_VERSION);
        rec.extend_from_slice(&(size as u16).to_be_bytes());

        if let Some(payload) = selected_payload {
            if size > 17 {
                let body_len = size - 17;
                let remaining = payload.len();
                let copy_len = remaining.min(body_len);
                if copy_len > 0 {
                    rec.extend_from_slice(&payload[..copy_len]);
                }
                if body_len > copy_len {
                    rec.extend_from_slice(&rng.bytes(body_len - copy_len));
                }
                rec.push(0x16); // inner content type marker (handshake)
                rec.extend_from_slice(&rng.bytes(16)); // AEAD-like tag
            } else {
                rec.extend_from_slice(&rng.bytes(size));
            }
        } else if size > 17 {
            let body_len = size - 17;
            let mut body = Vec::with_capacity(body_len);
            if idx == 0
                && let Some(marker) = &alpn_marker
            {
                if marker.len() <= body_len {
                    body.extend_from_slice(marker);
                    if body_len > marker.len() {
                        body.extend_from_slice(&rng.bytes(body_len - marker.len()));
                    }
                } else {
                    body.extend_from_slice(&rng.bytes(body_len));
                }
            } else {
                body.extend_from_slice(&rng.bytes(body_len));
            }
            rec.extend_from_slice(&body);
            rec.push(0x16); // inner content type marker (handshake)
            rec.extend_from_slice(&rng.bytes(16)); // AEAD-like tag
        } else {
            rec.extend_from_slice(&rng.bytes(size));
        }
        app_data.extend_from_slice(&rec);
    }

    // --- Combine ---
    // Optional NewSessionTicket mimic records (opaque ApplicationData for fingerprint).
    let mut tickets = Vec::new();
    for ticket_len in emulated_ticket_record_sizes(cached, new_session_tickets, rng) {
        let mut rec = Vec::with_capacity(5 + ticket_len);
        rec.push(TLS_RECORD_APPLICATION);
        rec.extend_from_slice(&TLS_VERSION);
        rec.extend_from_slice(&(ticket_len as u16).to_be_bytes());
        rec.extend_from_slice(&rng.bytes(ticket_len));
        tickets.extend_from_slice(&rec);
    }

    let mut response = Vec::with_capacity(
        server_hello.len() + change_cipher_spec.len() + app_data.len() + tickets.len(),
    );
    response.extend_from_slice(&server_hello);
    response.extend_from_slice(&change_cipher_spec);
    response.extend_from_slice(&app_data);
    response.extend_from_slice(&tickets);

    // --- HMAC ---
    let mut hmac_input = Vec::with_capacity(TLS_DIGEST_LEN + response.len());
    hmac_input.extend_from_slice(client_digest);
    hmac_input.extend_from_slice(&response);
    let digest = sha256_hmac(secret, &hmac_input);
    response[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].copy_from_slice(&digest);

    response
}

#[cfg(test)]
#[path = "tests/emulator_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "tests/emulator_profile_fidelity_security_tests.rs"]
mod emulator_profile_fidelity_security_tests;

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use crate::tls_front::types::{
        CachedTlsData, ParsedServerHello, TlsBehaviorProfile, TlsCertPayload, TlsProfileSource,
    };

    use super::{
        build_compact_cert_info_payload, build_emulated_server_hello,
        hash_compact_cert_info_payload,
    };
    use crate::crypto::SecureRandom;
    use crate::protocol::constants::{
        TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE,
    };
    use crate::protocol::tls::ClientHelloTlsVersion;

    fn first_app_data_payload(response: &[u8]) -> &[u8] {
        let hello_len = u16::from_be_bytes([response[3], response[4]]) as usize;
        let ccs_start = 5 + hello_len;
        let ccs_len =
            u16::from_be_bytes([response[ccs_start + 3], response[ccs_start + 4]]) as usize;
        let app_start = ccs_start + 5 + ccs_len;
        let app_len =
            u16::from_be_bytes([response[app_start + 3], response[app_start + 4]]) as usize;
        &response[app_start + 5..app_start + 5 + app_len]
    }

    fn make_cached(cert_payload: Option<TlsCertPayload>) -> CachedTlsData {
        CachedTlsData {
            server_hello_template: ParsedServerHello {
                version: [0x03, 0x03],
                random: [0u8; 32],
                session_id: Vec::new(),
                cipher_suite: [0x13, 0x01],
                compression: 0,
                extensions: Vec::new(),
            },
            cert_info: None,
            cert_payload,
            app_data_records_sizes: vec![64],
            total_app_data_len: 64,
            behavior_profile: TlsBehaviorProfile::default(),
            fetched_at: SystemTime::now(),
            domain: "example.com".to_string(),
        }
    }

    #[test]
    fn test_build_emulated_server_hello_uses_cached_cert_payload() {
        let cert_msg = vec![0x0b, 0x00, 0x00, 0x05, 0x00, 0xaa, 0xbb, 0xcc, 0xdd];
        let cached = make_cached(Some(TlsCertPayload {
            cert_chain_der: vec![vec![0x30, 0x01, 0x00]],
            certificate_message: cert_msg.clone(),
        }));
        let rng = SecureRandom::new();
        let response = build_emulated_server_hello(
            b"secret",
            &[0x11; 32],
            &[0x22; 16],
            &cached,
            true,
            true,
            ClientHelloTlsVersion::Tls12,
            &rng,
            None,
            0,
        );

        assert_eq!(response[0], TLS_RECORD_HANDSHAKE);
        let hello_len = u16::from_be_bytes([response[3], response[4]]) as usize;
        let ccs_start = 5 + hello_len;
        assert_eq!(response[ccs_start], TLS_RECORD_CHANGE_CIPHER);
        let app_start = ccs_start + 6;
        assert_eq!(response[app_start], TLS_RECORD_APPLICATION);

        let payload = first_app_data_payload(&response);
        assert!(payload.starts_with(&cert_msg));
    }

    #[test]
    fn test_build_emulated_server_hello_random_fallback_when_no_cert_payload() {
        let cached = make_cached(None);
        let rng = SecureRandom::new();
        let response = build_emulated_server_hello(
            b"secret",
            &[0x22; 32],
            &[0x33; 16],
            &cached,
            true,
            true,
            ClientHelloTlsVersion::Tls12,
            &rng,
            None,
            0,
        );

        let payload = first_app_data_payload(&response);
        assert!(payload.len() >= 64);
        assert_eq!(payload[payload.len() - 17], 0x16);
    }

    #[test]
    fn test_build_emulated_server_hello_uses_compact_payload_after_first() {
        let cert_msg = vec![0x0b, 0x00, 0x00, 0x05, 0x00, 0xaa, 0xbb, 0xcc, 0xdd];
        let mut cached = make_cached(Some(TlsCertPayload {
            cert_chain_der: vec![vec![0x30, 0x01, 0x00]],
            certificate_message: cert_msg,
        }));
        cached.cert_info = Some(crate::tls_front::types::ParsedCertificateInfo {
            not_after_unix: Some(1_900_000_000),
            not_before_unix: Some(1_700_000_000),
            issuer_cn: Some("Issuer".to_string()),
            subject_cn: Some("example.com".to_string()),
            san_names: vec!["example.com".to_string(), "www.example.com".to_string()],
        });

        let rng = SecureRandom::new();
        let response = build_emulated_server_hello(
            b"secret",
            &[0x44; 32],
            &[0x55; 16],
            &cached,
            false,
            true,
            ClientHelloTlsVersion::Tls12,
            &rng,
            None,
            0,
        );

        let payload = first_app_data_payload(&response);
        let expected_hashed_payload = build_compact_cert_info_payload(
            cached
                .cert_info
                .as_ref()
                .expect("test fixture must provide certificate info"),
        )
        .and_then(hash_compact_cert_info_payload)
        .expect("compact certificate info payload must be present for this test");
        let copied_prefix_len = expected_hashed_payload
            .len()
            .min(payload.len().saturating_sub(17));
        assert_eq!(
            &payload[..copied_prefix_len],
            &expected_hashed_payload[..copied_prefix_len]
        );
    }

    #[test]
    fn test_build_emulated_server_hello_tls13_never_uses_cert_payload() {
        let cert_msg = vec![0x0b, 0x00, 0x00, 0x05, 0x00, 0xaa, 0xbb, 0xcc, 0xdd];
        let cached = make_cached(Some(TlsCertPayload {
            cert_chain_der: vec![vec![0x30, 0x01, 0x00]],
            certificate_message: cert_msg.clone(),
        }));

        let rng = SecureRandom::new();
        let response = build_emulated_server_hello(
            b"secret",
            &[0x56; 32],
            &[0x78; 16],
            &cached,
            true,
            true,
            ClientHelloTlsVersion::Tls13,
            &rng,
            None,
            0,
        );

        let payload = first_app_data_payload(&response);
        assert!(
            !payload.starts_with(&cert_msg),
            "TLS 1.3 response path must not expose certificate payload bytes"
        );
    }

    #[test]
    fn test_build_emulated_server_hello_compact_disabled_skips_compact_payload() {
        let mut cached = make_cached(None);
        cached.cert_info = Some(crate::tls_front::types::ParsedCertificateInfo {
            not_after_unix: Some(1_900_000_000),
            not_before_unix: Some(1_700_000_000),
            issuer_cn: Some("Issuer".to_string()),
            subject_cn: Some("example.com".to_string()),
            san_names: vec!["example.com".to_string()],
        });

        let rng = SecureRandom::new();
        let response = build_emulated_server_hello(
            b"secret",
            &[0x90; 32],
            &[0x91; 16],
            &cached,
            false,
            false,
            ClientHelloTlsVersion::Tls12,
            &rng,
            Some(b"h2".to_vec()),
            0,
        );

        let payload = first_app_data_payload(&response);
        let expected_alpn_marker = [0x00u8, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2'];
        assert!(
            payload.starts_with(&expected_alpn_marker),
            "when compact mode is disabled and no full cert payload exists, the random/alpn path must be used"
        );
    }

    #[test]
    fn test_build_emulated_server_hello_ignores_tail_records_for_profiled_tls() {
        let mut cached = make_cached(None);
        cached.app_data_records_sizes = vec![27, 3905, 537, 69];
        cached.total_app_data_len = 4538;
        cached.behavior_profile.source = TlsProfileSource::Merged;
        cached.behavior_profile.app_data_record_sizes = vec![27, 3905, 537];
        cached.behavior_profile.ticket_record_sizes = vec![69];

        let rng = SecureRandom::new();
        let response = build_emulated_server_hello(
            b"secret",
            &[0x12; 32],
            &[0x34; 16],
            &cached,
            false,
            true,
            ClientHelloTlsVersion::Tls13,
            &rng,
            None,
            0,
        );

        let hello_len = u16::from_be_bytes([response[3], response[4]]) as usize;
        let ccs_start = 5 + hello_len;
        let app_start = ccs_start + 6;
        let app_len =
            u16::from_be_bytes([response[app_start + 3], response[app_start + 4]]) as usize;
        assert_eq!(response[app_start], TLS_RECORD_APPLICATION);
        assert_eq!(app_len, 64);
        assert_eq!(app_start + 5 + app_len, response.len());
    }
}
