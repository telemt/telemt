use std::net::{IpAddr, SocketAddr};

use hyper::Request;
use hyper::header;
use ipnetwork::IpNetwork;

use crate::config::WebClientIpSource;

/// Parses one lowercase canonical Host value restricted to the public HTTPS port.
pub(in crate::web::http) fn canonical_request_host<B>(request: &Request<B>) -> Option<&str> {
    let values = request.headers().get_all(header::HOST);
    let mut values = values.iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let authority = value.parse::<hyper::http::uri::Authority>().ok()?;
    if authority.port_u16().is_some_and(|port| port != 443) {
        return None;
    }
    let host = value.strip_suffix(":443").unwrap_or(value);
    if authority.host() != host || host.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    Some(host)
}

/// Canonicalizes one ASCII DNS authority into bounded request-local storage.
/// Only the literal public HTTPS port is permitted; forwarding headers are ignored.
pub(in crate::web::http) fn wildcard_request_host<'a, B>(
    request: &Request<B>,
    storage: &'a mut [u8; 253],
) -> Option<&'a str> {
    let mut values = request.headers().get_all(header::HOST).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let host = value.strip_suffix(":443").unwrap_or(value);
    if host.len() > storage.len() || !host.contains('.') || !host.is_ascii() {
        return None;
    }
    for (out, byte) in storage.iter_mut().zip(host.bytes()) {
        *out = byte.to_ascii_lowercase();
    }
    let host = std::str::from_utf8(&storage[..host.len()]).ok()?;
    if host.parse::<IpAddr>().is_ok()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    let last = host.rsplit('.').next()?;
    if last.bytes().all(|byte| byte.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(host)
}

/// Accepts one forwarded client address or the direct address of a trusted peer.
pub(in crate::web::http) fn client_ip<B>(
    request: &Request<B>,
    peer: SocketAddr,
    source: WebClientIpSource,
    trusted_proxy_cidrs: &[IpNetwork],
) -> Option<IpAddr> {
    if !trusted_proxy_cidrs
        .iter()
        .any(|network| network.contains(peer.ip()))
    {
        return None;
    }
    let header_name = match source {
        WebClientIpSource::XForwardedFor => "x-forwarded-for",
    };
    let values = request.headers().get_all(header_name);
    let mut values = values.iter();
    let Some(value) = values.next() else {
        return Some(peer.ip());
    };
    let value = value.to_str().ok()?;
    if values.next().is_some() || value.trim() != value || value.contains(',') {
        return None;
    }
    if value.is_empty() {
        return Some(peer.ip());
    }
    value.parse::<IpAddr>().ok()
}

/// Allows IP learning only for one explicit globally routable forwarded address.
pub(in crate::web::http) fn carrier_ip_learning_eligible<B>(
    request: &Request<B>,
    effective_ip: IpAddr,
) -> bool {
    let mut values = request.headers().get_all("x-forwarded-for").iter();
    let Some(value) = values.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if values.next().is_some()
        || value.trim() != value
        || value.contains(',')
        || value.parse::<IpAddr>().ok() != Some(effective_ip)
    {
        return false;
    }
    globally_routable(effective_ip)
}

fn globally_routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => globally_routable_v4(address),
        IpAddr::V6(address) => {
            if let Some(address) = address.to_ipv4_mapped() {
                return globally_routable_v4(address);
            }
            let segments = address.segments();
            !address.is_unspecified()
                && !address.is_loopback()
                && segments[0] & 0xfe00 != 0xfc00
                && segments[0] & 0xffc0 != 0xfe80
                && segments[0] & 0xff00 != 0xff00
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn globally_routable_v4(address: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}
