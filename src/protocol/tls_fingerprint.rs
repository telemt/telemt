//! Passive JA3 / JA4 TLS ClientHello fingerprinting.

use crate::crypto::hash::md5;
use crate::crypto::sha256;
use crate::protocol::constants::TLS_RECORD_HANDSHAKE;

const EXT_SNI: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsClientFingerprint {
    pub ja3: String,
    pub ja3_raw: String,
    pub ja4: String,
    pub ja4_raw: String,
}

#[derive(Default)]
struct ParsedClientHello {
    legacy_version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    supported_groups: Vec<u16>,
    ec_point_formats: Vec<u8>,
    signature_algorithms: Vec<u16>,
    supported_versions: Vec<u16>,
    alpn_first: Option<Vec<u8>>,
    sni_present: bool,
}

pub fn fingerprint_client_hello(handshake: &[u8]) -> Option<TlsClientFingerprint> {
    let parsed = parse_client_hello(handshake)?;
    let ja3_raw = ja3_raw(&parsed);
    let ja3 = hex::encode(md5(ja3_raw.as_bytes()));
    let (ja4, ja4_raw) = ja4(&parsed);

    Some(TlsClientFingerprint {
        ja3,
        ja3_raw,
        ja4,
        ja4_raw,
    })
}

fn parse_client_hello(handshake: &[u8]) -> Option<ParsedClientHello> {
    if handshake.len() < 5 || handshake[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }

    let record_len = read_u16_at(handshake, 3)? as usize;
    let record_end = 5usize.checked_add(record_len)?;
    if record_end > handshake.len() {
        return None;
    }

    let mut pos = 5usize;
    if *handshake.get(pos)? != 0x01 {
        return None;
    }
    pos = pos.checked_add(1)?;

    if pos + 3 > record_end {
        return None;
    }
    let handshake_len = ((usize::from(handshake[pos])) << 16)
        | ((usize::from(handshake[pos + 1])) << 8)
        | usize::from(handshake[pos + 2]);
    pos = pos.checked_add(3)?;
    let handshake_end = pos.checked_add(handshake_len)?;
    if handshake_end > record_end {
        return None;
    }

    if pos + 2 + 32 > handshake_end {
        return None;
    }
    let legacy_version = read_u16_at(handshake, pos)?;
    pos = pos.checked_add(2 + 32)?;

    let session_id_len = usize::from(*handshake.get(pos)?);
    pos = pos.checked_add(1)?.checked_add(session_id_len)?;
    if pos + 2 > handshake_end {
        return None;
    }

    let cipher_len = read_u16_at(handshake, pos)? as usize;
    pos = pos.checked_add(2)?;
    let cipher_end = pos.checked_add(cipher_len)?;
    if cipher_end > handshake_end || cipher_len % 2 != 0 {
        return None;
    }
    let mut ciphers = Vec::with_capacity(cipher_len / 2);
    while pos + 1 < cipher_end {
        let value = read_u16_at(handshake, pos)?;
        if !is_grease(value) {
            ciphers.push(value);
        }
        pos = pos.checked_add(2)?;
    }

    let comp_len = usize::from(*handshake.get(pos)?);
    pos = pos.checked_add(1)?.checked_add(comp_len)?;
    if pos > handshake_end {
        return None;
    }

    let mut parsed = ParsedClientHello {
        legacy_version,
        ciphers,
        ..ParsedClientHello::default()
    };

    if pos == handshake_end {
        return Some(parsed);
    }
    if pos + 2 > handshake_end {
        return None;
    }

    let ext_len = read_u16_at(handshake, pos)? as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_len)?;
    if ext_end > handshake_end {
        return None;
    }

    while pos + 4 <= ext_end {
        let etype = read_u16_at(handshake, pos)?;
        let elen = read_u16_at(handshake, pos + 2)? as usize;
        pos = pos.checked_add(4)?;
        let data_end = pos.checked_add(elen)?;
        if data_end > ext_end {
            return None;
        }
        let data = handshake.get(pos..data_end)?;

        if !is_grease(etype) {
            parsed.extensions.push(etype);
            match etype {
                EXT_SNI => parsed.sni_present = true,
                EXT_SUPPORTED_GROUPS => {
                    parsed.supported_groups = parse_u16_vector(data, 2)?;
                }
                EXT_EC_POINT_FORMATS => {
                    parsed.ec_point_formats = parse_u8_vector(data)?;
                }
                EXT_SIGNATURE_ALGORITHMS => {
                    parsed.signature_algorithms = parse_u16_vector(data, 2)?;
                }
                EXT_ALPN => {
                    parsed.alpn_first = parse_alpn_first(data)?;
                }
                EXT_SUPPORTED_VERSIONS => {
                    parsed.supported_versions = parse_u16_vector(data, 1)?;
                }
                _ => {}
            }
        }

        pos = data_end;
    }

    if pos != ext_end {
        return None;
    }

    Some(parsed)
}

fn parse_u16_vector(data: &[u8], len_prefix_len: usize) -> Option<Vec<u16>> {
    let (list_len, mut pos) = match len_prefix_len {
        1 => (usize::from(*data.first()?), 1usize),
        2 => (read_u16_at(data, 0)? as usize, 2usize),
        _ => return None,
    };
    let list_end = pos.checked_add(list_len)?;
    if list_end > data.len() || list_len % 2 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(list_len / 2);
    while pos + 1 < list_end {
        let value = read_u16_at(data, pos)?;
        if !is_grease(value) {
            out.push(value);
        }
        pos = pos.checked_add(2)?;
    }
    Some(out)
}

fn parse_u8_vector(data: &[u8]) -> Option<Vec<u8>> {
    let list_len = usize::from(*data.first()?);
    let list_start = 1usize;
    let list_end = list_start.checked_add(list_len)?;
    if list_end > data.len() {
        return None;
    }
    Some(data.get(list_start..list_end)?.to_vec())
}

fn parse_alpn_first(data: &[u8]) -> Option<Option<Vec<u8>>> {
    if data.len() < 2 {
        return None;
    }
    let list_len = read_u16_at(data, 0)? as usize;
    let mut pos = 2usize;
    let list_end = pos.checked_add(list_len)?;
    if list_end > data.len() {
        return None;
    }
    if pos == list_end {
        return Some(None);
    }

    let protocol_len = usize::from(*data.get(pos)?);
    pos = pos.checked_add(1)?;
    let protocol_end = pos.checked_add(protocol_len)?;
    if protocol_end > list_end {
        return None;
    }
    if protocol_len == 0 {
        return Some(None);
    }
    Some(Some(data.get(pos..protocol_end)?.to_vec()))
}

fn ja3_raw(parsed: &ParsedClientHello) -> String {
    format!(
        "{},{},{},{},{}",
        parsed.legacy_version,
        join_decimal_u16(&parsed.ciphers),
        join_decimal_u16(&parsed.extensions),
        join_decimal_u16(&parsed.supported_groups),
        join_decimal_u8(&parsed.ec_point_formats)
    )
}

fn ja4(parsed: &ParsedClientHello) -> (String, String) {
    let a = format!(
        "t{}{}{:02}{:02}{}",
        ja4_version_code(parsed),
        if parsed.sni_present { "d" } else { "i" },
        count_ja4(parsed.ciphers.len()),
        count_ja4(parsed.extensions.len()),
        ja4_alpn_marker(parsed.alpn_first.as_deref())
    );

    let mut ciphers = parsed.ciphers.clone();
    ciphers.sort_unstable();
    let cipher_raw = join_hex_u16(&ciphers);
    let cipher_hash = if ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        sha256_truncated_12(&cipher_raw)
    };

    let mut extensions_for_hash = parsed
        .extensions
        .iter()
        .copied()
        .filter(|value| *value != EXT_SNI && *value != EXT_ALPN)
        .collect::<Vec<_>>();
    extensions_for_hash.sort_unstable();
    let extension_raw = join_hex_u16(&extensions_for_hash);
    let signature_raw = join_hex_u16(&parsed.signature_algorithms);
    let extension_hash_input = if signature_raw.is_empty() {
        extension_raw.clone()
    } else {
        format!("{extension_raw}_{signature_raw}")
    };
    let extension_hash = if extensions_for_hash.is_empty() {
        "000000000000".to_string()
    } else {
        sha256_truncated_12(&extension_hash_input)
    };

    (
        format!("{a}_{cipher_hash}_{extension_hash}"),
        format!("{a}_{cipher_raw}_{extension_hash_input}"),
    )
}

fn ja4_version_code(parsed: &ParsedClientHello) -> &'static str {
    let version = parsed
        .supported_versions
        .iter()
        .copied()
        .max()
        .unwrap_or(parsed.legacy_version);
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn ja4_alpn_marker(alpn_first: Option<&[u8]>) -> String {
    let Some(value) = alpn_first else {
        return "00".to_string();
    };
    let Some(first) = value.first().copied() else {
        return "00".to_string();
    };
    let last = value.last().copied().unwrap_or(first);
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        return format!("{}{}", first as char, last as char);
    }

    let encoded = hex::encode(value);
    if encoded.is_empty() {
        return "00".to_string();
    }
    let first_hex = encoded.as_bytes()[0] as char;
    let last_hex = encoded.as_bytes()[encoded.len().saturating_sub(1)] as char;
    format!("{first_hex}{last_hex}")
}

fn count_ja4(count: usize) -> usize {
    count.min(99)
}

fn sha256_truncated_12(input: &str) -> String {
    let mut encoded = hex::encode(sha256(input.as_bytes()));
    encoded.truncate(12);
    encoded
}

fn join_decimal_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn join_decimal_u8(values: &[u8]) -> String {
    values
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn join_hex_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn read_u16_at(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *buf.get(pos)?,
        *buf.get(pos.checked_add(1)?)?,
    ]))
}

fn is_grease(value: u16) -> bool {
    let high = (value >> 8) as u8;
    let low = value as u8;
    high == low && (high & 0x0f) == 0x0a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_client_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&10u16.to_be_bytes());
        body.extend_from_slice(&[0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f, 0x00, 0xff]);
        body.push(1);
        body.push(0);

        let mut extensions = Vec::new();
        append_ext(&mut extensions, EXT_SNI, &[0, 0]);
        append_ext(&mut extensions, EXT_ALPN, &[0, 3, 2, b'h', b'2']);
        append_ext(
            &mut extensions,
            EXT_SUPPORTED_GROUPS,
            &[0, 6, 0x0a, 0x0a, 0x00, 0x17, 0x00, 0x1d],
        );
        append_ext(&mut extensions, EXT_EC_POINT_FORMATS, &[1, 0]);
        append_ext(
            &mut extensions,
            EXT_SIGNATURE_ALGORITHMS,
            &[0, 4, 0x04, 0x03, 0x08, 0x04],
        );
        append_ext(
            &mut extensions,
            EXT_SUPPORTED_VERSIONS,
            &[4, 0x03, 0x04, 0x03, 0x03],
        );
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut record = Vec::new();
        record.push(TLS_RECORD_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        record.push(0x01);
        record.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        record.extend_from_slice(&body);
        record
    }

    fn append_ext(out: &mut Vec<u8>, etype: u16, data: &[u8]) {
        out.extend_from_slice(&etype.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    #[test]
    fn ja3_and_ja4_ignore_grease_and_remain_stable() {
        let fp = fingerprint_client_hello(&sample_client_hello())
            .expect("sample ClientHello must fingerprint");
        assert_eq!(
            fp.ja3_raw,
            "771,4865-4866-49199-255,0-16-10-11-13-43,23-29,0"
        );
        assert!(fp.ja4.starts_with("t13d0406h2_"));
    }

    #[test]
    fn malformed_client_hello_returns_none() {
        let mut hello = sample_client_hello();
        hello.truncate(12);
        assert!(fingerprint_client_hello(&hello).is_none());
    }
}
