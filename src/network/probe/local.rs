use super::*;

pub(super) fn detect_local_ip_v4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

pub(super) fn detect_local_ip_v6() -> Option<Ipv6Addr> {
    let socket = UdpSocket::bind("[::]:0").ok()?;
    socket.connect("[2001:4860:4860::8888]:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V6(v6) => Some(v6),
        _ => None,
    }
}

pub fn detect_interface_ipv4() -> Option<Ipv4Addr> {
    detect_local_ip_v4()
}

pub fn detect_interface_ipv6() -> Option<Ipv6Addr> {
    detect_local_ip_v6()
}

pub fn is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_bogon_v4(v4),
        IpAddr::V6(v6) => is_bogon_v6(v6),
    }
}

pub fn is_bogon_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
        return true;
    }
    if octets[0] == 0 {
        return true;
    }
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    if octets[0] == 198 && (octets[1] & 0xFE) == 18 {
        return true;
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    if ip.is_multicast() {
        return true;
    }
    if octets[0] >= 240 {
        return true;
    }
    if ip.is_broadcast() {
        return true;
    }
    false
}

pub fn is_bogon_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_unique_local() {
        return true;
    }
    let segs = ip.segments();
    if (segs[0] & 0xFFC0) == 0xFE80 {
        return true;
    }
    if segs[0..5] == [0, 0, 0, 0, 0] && segs[5] == 0xFFFF {
        return true;
    }
    if segs[0] == 0x0100 && segs[1..4] == [0, 0, 0] {
        return true;
    }
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return true;
    }
    if segs[0] == 0x2002 {
        return true;
    }
    if ip.is_multicast() {
        return true;
    }
    false
}

pub fn log_probe_result(probe: &NetworkProbe, decision: &NetworkDecision) {
    info!(
        ipv4 = probe
            .detected_ipv4
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into()),
        ipv6 = probe
            .detected_ipv6
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into()),
        reflected_v4 = probe
            .reflected_ipv4
            .as_ref()
            .map(|v| v.ip().to_string())
            .unwrap_or_else(|| "-".into()),
        reflected_v6 = probe
            .reflected_ipv6
            .as_ref()
            .map(|v| v.ip().to_string())
            .unwrap_or_else(|| "-".into()),
        ipv4_bogon = probe.ipv4_is_bogon,
        ipv6_bogon = probe.ipv6_is_bogon,
        ipv4_me = decision.ipv4_me,
        ipv6_me = decision.ipv6_me,
        ipv4_dc = decision.ipv4_dc,
        ipv6_dc = decision.ipv6_dc,
        prefer = decision.effective_prefer,
        multipath = decision.effective_multipath,
        "Network capabilities resolved"
    );
}
