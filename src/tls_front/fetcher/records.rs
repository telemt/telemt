use super::*;

pub(super) async fn read_tls_record<S>(stream: &mut S) -> Result<(u8, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok((header[0], body))
}

pub(super) fn parse_server_hello(body: &[u8]) -> Option<ParsedServerHello> {
    if body.len() < 4 || body[0] != 0x02 {
        return None;
    }

    let msg_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    if msg_len + 4 > body.len() {
        return None;
    }

    let mut pos = 4;
    let version = [*body.get(pos)?, *body.get(pos + 1)?];
    pos += 2;

    let mut random = [0u8; 32];
    random.copy_from_slice(body.get(pos..pos + 32)?);
    pos += 32;

    let session_len = *body.get(pos)? as usize;
    pos += 1;
    let session_id = body.get(pos..pos + session_len)?.to_vec();
    pos += session_len;

    let cipher_suite = [*body.get(pos)?, *body.get(pos + 1)?];
    pos += 2;

    let compression = *body.get(pos)?;
    pos += 1;

    let ext_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 2;
    let ext_end = pos.checked_add(ext_len)?;
    if ext_end > body.len() {
        return None;
    }

    let mut extensions = Vec::new();
    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let elen = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        let data = body.get(pos..pos + elen)?.to_vec();
        pos += elen;
        extensions.push(TlsExtension {
            ext_type: etype,
            data,
        });
    }

    Some(ParsedServerHello {
        version,
        random,
        session_id,
        cipher_suite,
        compression,
        extensions,
    })
}

pub(super) fn derive_behavior_profile(records: &[(u8, Vec<u8>)]) -> TlsBehaviorProfile {
    let mut change_cipher_spec_count = 0u8;
    let mut app_data_record_sizes = Vec::new();

    for (record_type, body) in records {
        match *record_type {
            TLS_RECORD_CHANGE_CIPHER => {
                change_cipher_spec_count = change_cipher_spec_count.saturating_add(1);
            }
            TLS_RECORD_APPLICATION => {
                app_data_record_sizes.push(body.len());
            }
            _ => {}
        }
    }

    let mut ticket_record_sizes = Vec::new();
    while app_data_record_sizes
        .last()
        .is_some_and(|size| *size <= 256 && ticket_record_sizes.len() < 2)
    {
        if let Some(size) = app_data_record_sizes.pop() {
            ticket_record_sizes.push(size);
        }
    }
    ticket_record_sizes.reverse();

    TlsBehaviorProfile {
        change_cipher_spec_count: change_cipher_spec_count.max(1),
        app_data_record_sizes,
        ticket_record_sizes,
        source: TlsProfileSource::Raw,
        ..TlsBehaviorProfile::default()
    }
}

pub(super) fn parse_cert_info(certs: &[CertificateDer<'static>]) -> Option<ParsedCertificateInfo> {
    let first = certs.first()?;
    let (_rem, cert) = X509Certificate::from_der(first.as_ref()).ok()?;

    let not_before = Some(cert.validity().not_before.to_datetime().unix_timestamp());
    let not_after = Some(cert.validity().not_after.to_datetime().unix_timestamp());

    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    let san_names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    x509_parser::extensions::GeneralName::DNSName(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(ParsedCertificateInfo {
        not_after_unix: not_after,
        not_before_unix: not_before,
        issuer_cn,
        subject_cn,
        san_names,
    })
}

pub(super) fn u24_bytes(value: usize) -> Option<[u8; 3]> {
    if value > 0x00ff_ffff {
        return None;
    }
    Some([
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ])
}
