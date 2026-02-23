use crate::crypto::{sha256_hmac, SecureRandom};
use crate::protocol::constants::{
    TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE, TLS_VERSION,
};
use crate::protocol::tls::{TLS_DIGEST_LEN, TLS_DIGEST_POS, gen_fake_x25519_key};
use crate::tls_front::types::CachedTlsData;

const MIN_APP_DATA: usize = 64;
const MAX_APP_DATA: usize = 16640; // RFC 8446 §5.2 allows up to 2^14 + 256

fn jitter_and_clamp_sizes(sizes: &[usize], rng: &SecureRandom) -> Vec<usize> {
    sizes
        .iter()
        .map(|&size| {
            let base = size.max(MIN_APP_DATA).min(MAX_APP_DATA);
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

fn ensure_payload_capacity(mut sizes: Vec<usize>, payload_len: usize) -> Vec<usize> {
    if payload_len == 0 {
        return sizes;
    }

    let mut total = sizes.iter().sum::<usize>();
    if total >= payload_len {
        return sizes;
    }

    if let Some(last) = sizes.last_mut() {
        let free = MAX_APP_DATA.saturating_sub(*last);
        let grow = free.min(payload_len - total);
        *last += grow;
        total += grow;
    }

    while total < payload_len {
        let remaining = payload_len - total;
        let chunk = remaining.min(MAX_APP_DATA).max(MIN_APP_DATA);
        sizes.push(chunk);
        total += chunk;
    }

    sizes
}

/// Build a ServerHello + CCS + ApplicationData sequence using cached TLS metadata.
pub fn build_emulated_server_hello(
    secret: &[u8],
    client_digest: &[u8; TLS_DIGEST_LEN],
    session_id: &[u8],
    cached: &CachedTlsData,
    rng: &SecureRandom,
    alpn: Option<Vec<u8>>,
    new_session_tickets: u8,
) -> Vec<u8> {
    // --- ServerHello ---
    let mut extensions = Vec::new();
    // KeyShare (x25519)
    let key = gen_fake_x25519_key(rng);
    extensions.extend_from_slice(&0x0033u16.to_be_bytes()); // key_share
    extensions.extend_from_slice(&(2 + 2 + 32u16).to_be_bytes()); // len
    extensions.extend_from_slice(&0x001du16.to_be_bytes()); // X25519
    extensions.extend_from_slice(&(32u16).to_be_bytes());
    extensions.extend_from_slice(&key);
    // supported_versions (TLS1.3)
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&(2u16).to_be_bytes());
    extensions.extend_from_slice(&0x0304u16.to_be_bytes());
    if let Some(alpn_proto) = &alpn {
        extensions.extend_from_slice(&0x0010u16.to_be_bytes());
        let list_len: u16 = 1 + alpn_proto.len() as u16;
        let ext_len: u16 = 2 + list_len;
        extensions.extend_from_slice(&ext_len.to_be_bytes());
        extensions.extend_from_slice(&list_len.to_be_bytes());
        extensions.push(alpn_proto.len() as u8);
        extensions.extend_from_slice(alpn_proto);
    }

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
    let change_cipher_spec = [
        TLS_RECORD_CHANGE_CIPHER,
        TLS_VERSION[0],
        TLS_VERSION[1],
        0x00,
        0x01,
        0x01,
    ];

    // --- ApplicationData (fake encrypted records) ---
    // Use the same number and sizes of ApplicationData records as the cached server.
    let mut sizes = cached.app_data_records_sizes.clone();
    if sizes.is_empty() {
        sizes.push(cached.total_app_data_len.max(1024));
    }
    let mut sizes = jitter_and_clamp_sizes(&sizes, rng);
    let cert_payload = cached
        .cert_payload
        .as_ref()
        .map(|payload| payload.certificate_message.as_slice())
        .filter(|payload| !payload.is_empty());

    if let Some(payload) = cert_payload {
        sizes = ensure_payload_capacity(sizes, payload.len());
    }

    let mut app_data = Vec::new();
    let mut payload_offset = 0usize;
    for size in sizes {
        let mut rec = Vec::with_capacity(5 + size);
        rec.push(TLS_RECORD_APPLICATION);
        rec.extend_from_slice(&TLS_VERSION);
        rec.extend_from_slice(&(size as u16).to_be_bytes());

        if let Some(payload) = cert_payload {
            let remaining = payload.len().saturating_sub(payload_offset);
            let copy_len = remaining.min(size);
            if copy_len > 0 {
                rec.extend_from_slice(&payload[payload_offset..payload_offset + copy_len]);
                payload_offset += copy_len;
            }
            if size > copy_len {
                rec.extend_from_slice(&rng.bytes(size - copy_len));
            }
        } else {
            if size > 17 {
                let body_len = size - 17;
                rec.extend_from_slice(&rng.bytes(body_len));
                rec.push(0x16); // inner content type marker (handshake)
                rec.extend_from_slice(&rng.bytes(16)); // AEAD-like tag
            } else {
                rec.extend_from_slice(&rng.bytes(size));
            }
        }
        app_data.extend_from_slice(&rec);
    }

    // --- Combine ---
    // Optional NewSessionTicket mimic records (opaque ApplicationData for fingerprint).
    let mut tickets = Vec::new();
    if new_session_tickets > 0 {
        for _ in 0..new_session_tickets {
            let ticket_len: usize = rng.range(48) + 48;
            let mut rec = Vec::with_capacity(5 + ticket_len);
            rec.push(TLS_RECORD_APPLICATION);
            rec.extend_from_slice(&TLS_VERSION);
            rec.extend_from_slice(&(ticket_len as u16).to_be_bytes());
            rec.extend_from_slice(&rng.bytes(ticket_len));
            tickets.extend_from_slice(&rec);
        }
    }

    let mut response = Vec::with_capacity(server_hello.len() + change_cipher_spec.len() + app_data.len() + tickets.len());
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
mod tests {
    use std::time::SystemTime;

    use crate::tls_front::types::{CachedTlsData, ParsedServerHello, TlsCertPayload};

    use super::build_emulated_server_hello;
    use crate::crypto::SecureRandom;
    use crate::protocol::constants::{
        TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER, TLS_RECORD_HANDSHAKE,
    };

    fn first_app_data_payload(response: &[u8]) -> &[u8] {
        let hello_len = u16::from_be_bytes([response[3], response[4]]) as usize;
        let ccs_start = 5 + hello_len;
        let ccs_len = u16::from_be_bytes([response[ccs_start + 3], response[ccs_start + 4]]) as usize;
        let app_start = ccs_start + 5 + ccs_len;
        let app_len = u16::from_be_bytes([response[app_start + 3], response[app_start + 4]]) as usize;
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
            &rng,
            None,
            0,
        );

        let payload = first_app_data_payload(&response);
        assert!(payload.len() >= 64);
        assert_eq!(payload[payload.len() - 17], 0x16);
    }
}
