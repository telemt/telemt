use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

use serde_json::Value;

use crate::config::ProxyConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HealthcheckMode {
    Liveness,
    Ready,
}

impl HealthcheckMode {
    pub(crate) fn from_cli_arg(value: &str) -> Option<Self> {
        match value {
            "liveness" => Some(Self::Liveness),
            "ready" => Some(Self::Ready),
            _ => None,
        }
    }

    fn request_path(self) -> &'static str {
        match self {
            Self::Liveness => "/v1/health",
            Self::Ready => "/v1/health/ready",
        }
    }
}

pub(crate) fn run(config_path: &str, mode: HealthcheckMode) -> i32 {
    match run_inner(config_path, mode) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("[telemt] healthcheck failed: {error}");
            1
        }
    }
}

fn run_inner(config_path: &str, mode: HealthcheckMode) -> Result<(), String> {
    let config =
        ProxyConfig::load(config_path).map_err(|error| format!("config load failed: {error}"))?;
    let api_cfg = &config.server.api;
    if !api_cfg.enabled {
        return Ok(());
    }

    let listen: SocketAddr = api_cfg
        .listen
        .parse()
        .map_err(|_| format!("invalid API listen address: {}", api_cfg.listen))?;
    if listen.port() == 0 {
        return Err("API listen port is 0".to_string());
    }
    let target = probe_target(listen);

    let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(2))
        .map_err(|error| format!("connect {target} failed: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set read timeout failed: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set write timeout failed: {error}"))?;

    let request = build_request(target, mode.request_path(), &api_cfg.auth_header);
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("request write failed: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("request flush failed: {error}"))?;

    let mut raw_response = Vec::new();
    stream
        .read_to_end(&mut raw_response)
        .map_err(|error| format!("response read failed: {error}"))?;
    let response =
        String::from_utf8(raw_response).map_err(|_| "response is not valid UTF-8".to_string())?;

    let (status_code, body) = split_response(&response)?;
    if status_code != 200 {
        return Err(format!("HTTP status {status_code}"));
    }

    validate_payload(mode, body)?;
    Ok(())
}

fn probe_target(listen: SocketAddr) -> SocketAddr {
    match listen {
        SocketAddr::V4(addr) => {
            let ip = if addr.ip().is_unspecified() {
                Ipv4Addr::LOCALHOST
            } else {
                *addr.ip()
            };
            SocketAddr::from((ip, addr.port()))
        }
        SocketAddr::V6(addr) => {
            let ip = if addr.ip().is_unspecified() {
                Ipv6Addr::LOCALHOST
            } else {
                *addr.ip()
            };
            SocketAddr::from((ip, addr.port()))
        }
    }
}

fn build_request(target: SocketAddr, path: &str, auth_header: &str) -> String {
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        target
    );
    if !auth_header.is_empty() {
        request.push_str("Authorization: ");
        request.push_str(auth_header);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request
}

fn split_response(response: &str) -> Result<(u16, &str), String> {
    let header_end = response
        .find("\r\n\r\n")
        .ok_or_else(|| "invalid HTTP response headers".to_string())?;
    let header = &response[..header_end];
    let body = &response[header_end + 4..];
    let status_line = header
        .lines()
        .next()
        .ok_or_else(|| "missing HTTP status line".to_string())?;
    let status_code = parse_status_code(status_line)?;
    Ok((status_code, body))
}

fn parse_status_code(status_line: &str) -> Result<u16, String> {
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| "missing HTTP version".to_string())?;
    if !version.starts_with("HTTP/") {
        return Err(format!("invalid HTTP status line: {status_line}"));
    }
    let code = parts
        .next()
        .ok_or_else(|| "missing HTTP status code".to_string())?;
    code.parse::<u16>()
        .map_err(|_| format!("invalid HTTP status code: {code}"))
}

fn validate_payload(mode: HealthcheckMode, body: &str) -> Result<(), String> {
    let payload: Value =
        serde_json::from_str(body).map_err(|_| "response body is not valid JSON".to_string())?;
    if payload.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err("response JSON has ok=false".to_string());
    }

    let data = payload
        .get("data")
        .ok_or_else(|| "response JSON has no data field".to_string())?;
    match mode {
        HealthcheckMode::Liveness => {
            if data.get("status").and_then(Value::as_str) != Some("ok") {
                return Err("liveness status is not ok".to_string());
            }
        }
        HealthcheckMode::Ready => {
            if data.get("ready").and_then(Value::as_bool) != Some(true) {
                return Err("readiness flag is false".to_string());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{HealthcheckMode, parse_status_code, split_response, validate_payload};

    #[test]
    fn parse_status_code_reads_http_200() {
        let status = parse_status_code("HTTP/1.1 200 OK").expect("must parse status");
        assert_eq!(status, 200);
    }

    #[test]
    fn split_response_extracts_status_and_body() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let (status, body) = split_response(response).expect("must split response");
        assert_eq!(status, 200);
        assert_eq!(body, "{\"ok\":true}");
    }

    #[test]
    fn validate_payload_accepts_liveness_contract() {
        let body = "{\"ok\":true,\"data\":{\"status\":\"ok\"}}";
        validate_payload(HealthcheckMode::Liveness, body).expect("liveness payload must pass");
    }

    #[test]
    fn validate_payload_rejects_not_ready() {
        let body = "{\"ok\":true,\"data\":{\"ready\":false}}";
        let result = validate_payload(HealthcheckMode::Ready, body);
        assert!(result.is_err());
    }
}
