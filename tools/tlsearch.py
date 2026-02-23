#!/usr/bin/env python3
"""
TLS Profile Inspector

Usage:
  python3 tools/tlsearch.py
  python3 tools/tlsearch.py tlsfront
  python3 tools/tlsearch.py tlsfront/petrovich.ru.json
  python3 tools/tlsearch.py tlsfront --only-current
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

EXT_NAMES = {
    0: "server_name",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "alpn",
    18: "signed_certificate_timestamp",
    21: "padding",
    23: "extended_master_secret",
    35: "session_ticket",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
}

CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

NAMED_GROUPS = {
    0x001D: "x25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
}


@dataclass
class ProfileRecognition:
    schema: str
    mode: str
    has_cert_info: bool
    has_full_cert_payload: bool
    cert_message_len: int
    cert_chain_count: int
    cert_chain_total_len: int
    issues: list[str]


def to_hex(data: Iterable[int]) -> str:
    return "".join(f"{b:02x}" for b in data)


def read_u16be(data: list[int], off: int = 0) -> int:
    return (data[off] << 8) | data[off + 1]


def normalize_u8_list(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    out: list[int] = []
    for item in value:
        if isinstance(item, int) and 0 <= item <= 0xFF:
            out.append(item)
        else:
            return []
    return out


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_int(value: Any, default: int = 0) -> int:
    return value if isinstance(value, int) else default


def decode_version_pair(v: list[int]) -> str:
    if len(v) != 2:
        return f"invalid({v})"
    ver = read_u16be(v)
    return f"0x{ver:04x} ({TLS_VERSIONS.get(ver, 'unknown')})"


def decode_cipher_suite(v: list[int]) -> str:
    if len(v) != 2:
        return f"invalid({v})"
    cs = read_u16be(v)
    name = CIPHER_NAMES.get(cs, "unknown")
    return f"0x{cs:04x} ({name})"


def decode_supported_versions(data: list[int]) -> str:
    if len(data) == 2:
        ver = read_u16be(data)
        return f"selected=0x{ver:04x} ({TLS_VERSIONS.get(ver, 'unknown')})"
    if not data:
        return "empty"
    if len(data) < 3:
        return f"raw={to_hex(data)}"
    vec_len = data[0]
    versions: list[str] = []
    for i in range(1, min(1 + vec_len, len(data)), 2):
        if i + 1 >= len(data):
            break
        ver = read_u16be(data, i)
        versions.append(f"0x{ver:04x}({TLS_VERSIONS.get(ver, 'unknown')})")
    return "offered=[" + ", ".join(versions) + "]"


def decode_key_share(data: list[int]) -> str:
    if len(data) < 4:
        return f"raw={to_hex(data)}"
    group = read_u16be(data, 0)
    key_len = read_u16be(data, 2)
    key_hex = to_hex(data[4 : 4 + min(key_len, len(data) - 4)])
    gname = NAMED_GROUPS.get(group, "unknown_group")
    return f"group=0x{group:04x}({gname}), key_len={key_len}, key={key_hex}"


def decode_alpn(data: list[int]) -> str:
    if len(data) < 3:
        return f"raw={to_hex(data)}"
    total = read_u16be(data, 0)
    pos = 2
    vals: list[str] = []
    limit = min(len(data), 2 + total)
    while pos < limit:
        ln = data[pos]
        pos += 1
        if pos + ln > limit:
            break
        raw = bytes(data[pos : pos + ln])
        pos += ln
        try:
            vals.append(raw.decode("ascii"))
        except UnicodeDecodeError:
            vals.append(raw.hex())
    return "protocols=[" + ", ".join(vals) + "]"


def decode_extension(ext_type: int, data: list[int]) -> str:
    if ext_type == 43:
        return decode_supported_versions(data)
    if ext_type == 51:
        return decode_key_share(data)
    if ext_type == 16:
        return decode_alpn(data)
    return f"raw={to_hex(data)}"


def ts_to_iso(ts: Any) -> str:
    if not isinstance(ts, int):
        return "-"
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()


def recognize_profile(obj: dict[str, Any]) -> ProfileRecognition:
    issues: list[str] = []

    sh = as_dict(obj.get("server_hello_template"))
    if not sh:
        issues.append("missing server_hello_template")

    version = normalize_u8_list(sh.get("version"))
    if version and len(version) != 2:
        issues.append("server_hello_template.version must have 2 bytes")

    app_sizes = obj.get("app_data_records_sizes")
    if not isinstance(app_sizes, list) or not app_sizes:
        issues.append("missing app_data_records_sizes")
    elif any((not isinstance(v, int) or v <= 0) for v in app_sizes):
        issues.append("app_data_records_sizes contains invalid values")

    if not isinstance(obj.get("total_app_data_len"), int):
        issues.append("missing total_app_data_len")

    cert_info = as_dict(obj.get("cert_info"))
    has_cert_info = bool(
        cert_info.get("subject_cn")
        or cert_info.get("issuer_cn")
        or cert_info.get("san_names")
        or isinstance(cert_info.get("not_before_unix"), int)
        or isinstance(cert_info.get("not_after_unix"), int)
    )

    cert_payload = as_dict(obj.get("cert_payload"))
    cert_message_len = 0
    cert_chain_count = 0
    cert_chain_total_len = 0
    has_full_cert_payload = False

    if cert_payload:
        cert_msg = normalize_u8_list(cert_payload.get("certificate_message"))
        if not cert_msg:
            issues.append("cert_payload.certificate_message is missing or invalid")
        else:
            cert_message_len = len(cert_msg)

        chain_raw = cert_payload.get("cert_chain_der")
        if not isinstance(chain_raw, list):
            issues.append("cert_payload.cert_chain_der is missing or invalid")
        else:
            for entry in chain_raw:
                cert = normalize_u8_list(entry)
                if cert:
                    cert_chain_count += 1
                    cert_chain_total_len += len(cert)
                else:
                    issues.append("cert_payload.cert_chain_der has invalid certificate entry")
                    break

        has_full_cert_payload = cert_message_len > 0 and cert_chain_count > 0
    elif obj.get("cert_payload") is not None:
        issues.append("cert_payload is not an object")

    if has_full_cert_payload:
        schema = "current"
        mode = "full-cert-payload"
    elif has_cert_info:
        schema = "current-compact"
        mode = "compact-cert-info"
    else:
        schema = "legacy"
        mode = "random-fallback"

    if issues:
        schema = f"{schema}+issues"

    return ProfileRecognition(
        schema=schema,
        mode=mode,
        has_cert_info=has_cert_info,
        has_full_cert_payload=has_full_cert_payload,
        cert_message_len=cert_message_len,
        cert_chain_count=cert_chain_count,
        cert_chain_total_len=cert_chain_total_len,
        issues=issues,
    )


def decode_profile(path: Path) -> tuple[str, ProfileRecognition]:
    obj: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    recognition = recognize_profile(obj)

    sh = as_dict(obj.get("server_hello_template"))
    version = normalize_u8_list(sh.get("version"))
    cipher = normalize_u8_list(sh.get("cipher_suite"))
    random_bytes = normalize_u8_list(sh.get("random"))
    session_id = normalize_u8_list(sh.get("session_id"))

    lines: list[str] = []
    lines.append(f"[{path.name}]")
    lines.append(f"  domain: {obj.get('domain', '-')}")
    lines.append(f"  profile.schema: {recognition.schema}")
    lines.append(f"  profile.mode: {recognition.mode}")
    lines.append(f"  profile.has_full_cert_payload: {recognition.has_full_cert_payload}")
    lines.append(f"  profile.has_cert_info: {recognition.has_cert_info}")
    if recognition.has_full_cert_payload:
        lines.append(f"  profile.cert_message_len: {recognition.cert_message_len}")
        lines.append(f"  profile.cert_chain_count: {recognition.cert_chain_count}")
        lines.append(f"  profile.cert_chain_total_len: {recognition.cert_chain_total_len}")
    if recognition.issues:
        lines.append("  profile.issues:")
        for issue in recognition.issues:
            lines.append(f"    - {issue}")

    lines.append(f"  tls.version: {decode_version_pair(version)}")
    lines.append(f"  tls.cipher: {decode_cipher_suite(cipher)}")
    lines.append(f"  tls.compression: {sh.get('compression', '-')}")
    lines.append(f"  tls.random: {to_hex(random_bytes)}")
    lines.append(f"  tls.session_id_len: {len(session_id)}")
    if session_id:
        lines.append(f"  tls.session_id: {to_hex(session_id)}")

    app_sizes = obj.get("app_data_records_sizes", [])
    if isinstance(app_sizes, list):
        lines.append("  app_data_records_sizes: " + ", ".join(str(v) for v in app_sizes))
    else:
        lines.append("  app_data_records_sizes: -")
    lines.append(f"  total_app_data_len: {obj.get('total_app_data_len', '-')}")

    cert = as_dict(obj.get("cert_info"))
    if cert:
        lines.append("  cert_info:")
        lines.append(f"    subject_cn: {cert.get('subject_cn') or '-'}")
        lines.append(f"    issuer_cn: {cert.get('issuer_cn') or '-'}")
        lines.append(f"    not_before: {ts_to_iso(cert.get('not_before_unix'))}")
        lines.append(f"    not_after:  {ts_to_iso(cert.get('not_after_unix'))}")
        sans = cert.get("san_names")
        if isinstance(sans, list) and sans:
            lines.append("    san_names: " + ", ".join(str(v) for v in sans))
        else:
            lines.append("    san_names: -")
    else:
        lines.append("  cert_info: -")

    exts = sh.get("extensions", [])
    if not isinstance(exts, list):
        exts = []
    lines.append(f"  extensions[{len(exts)}]:")
    for ext in exts:
        ext_obj = as_dict(ext)
        ext_type = as_int(ext_obj.get("ext_type"), -1)
        data = normalize_u8_list(ext_obj.get("data"))
        name = EXT_NAMES.get(ext_type, "unknown")
        decoded = decode_extension(ext_type, data)
        lines.append(f"    - type={ext_type} ({name}), len={len(data)}: {decoded}")

    lines.append("")
    return ("\n".join(lines), recognition)


def collect_files(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    return sorted(p for p in input_path.glob("*.json") if p.is_file())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode TLS profile JSON files and recognize current schema."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="tlsfront",
        help="Path to tlsfront directory or a single JSON file.",
    )
    parser.add_argument(
        "--only-current",
        action="store_true",
        help="Show only profiles recognized as current/full-cert-payload.",
    )
    args = parser.parse_args()

    base = Path(args.path)
    if not base.exists():
        print(f"Path not found: {base}")
        return 1

    files = collect_files(base)
    if not files:
        print(f"No JSON files found in: {base}")
        return 1

    printed = 0
    for path in files:
        try:
            rendered, recognition = decode_profile(path)
            if args.only_current and recognition.schema != "current":
                continue
            print(rendered, end="")
            printed += 1
        except Exception as e:  # noqa: BLE001
            print(f"[{path.name}] decode error: {e}\n")

    if args.only_current and printed == 0:
        print("No current profiles found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
