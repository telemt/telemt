#!/usr/bin/env python3
"""
TLS Profile JSON Decoder

Usage:
  python3 tlsfront/decode_profiles.py
  python3 tlsfront/decode_profiles.py tlsfront
  python3 tlsfront/decode_profiles.py tlsfront/petrovich.ru.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any


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


def to_hex(data: list[int]) -> str:
    return "".join(f"{b:02x}" for b in data)


def u16be(data: list[int], off: int = 0) -> int:
    return (data[off] << 8) | data[off + 1]


def decode_version_pair(v: list[int]) -> str:
    if len(v) != 2:
        return f"invalid({v})"
    ver = u16be(v)
    return f"0x{ver:04x} ({TLS_VERSIONS.get(ver, 'unknown')})"


def decode_cipher_suite(v: list[int]) -> str:
    if len(v) != 2:
        return f"invalid({v})"
    cs = u16be(v)
    name = CIPHER_NAMES.get(cs, "unknown")
    return f"0x{cs:04x} ({name})"


def decode_supported_versions(data: list[int]) -> str:
    if len(data) == 2:
        ver = u16be(data)
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
        ver = u16be(data, i)
        versions.append(f"0x{ver:04x}({TLS_VERSIONS.get(ver, 'unknown')})")
    return "offered=[" + ", ".join(versions) + "]"


def decode_key_share(data: list[int]) -> str:
    if len(data) < 4:
        return f"raw={to_hex(data)}"
    group = u16be(data, 0)
    key_len = u16be(data, 2)
    key_hex = to_hex(data[4 : 4 + min(key_len, len(data) - 4)])
    gname = NAMED_GROUPS.get(group, "unknown_group")
    return f"group=0x{group:04x}({gname}), key_len={key_len}, key={key_hex}"


def decode_alpn(data: list[int]) -> str:
    if len(data) < 3:
        return f"raw={to_hex(data)}"
    total = u16be(data, 0)
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


def ts_to_iso(ts: int | None) -> str:
    if ts is None:
        return "-"
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()


def decode_profile(path: Path) -> str:
    obj: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    sh = obj.get("server_hello_template", {})

    lines: list[str] = []
    lines.append(f"[{path.name}]")
    lines.append(f"  domain: {obj.get('domain', '-')}")
    lines.append(f"  tls.version: {decode_version_pair(sh.get('version', []))}")
    lines.append(f"  tls.cipher: {decode_cipher_suite(sh.get('cipher_suite', []))}")
    lines.append(f"  tls.compression: {sh.get('compression', '-')}")
    lines.append(f"  tls.random: {to_hex(sh.get('random', []))}")
    session_id = sh.get("session_id", [])
    lines.append(f"  tls.session_id_len: {len(session_id)}")
    if session_id:
        lines.append(f"  tls.session_id: {to_hex(session_id)}")
    lines.append(
        "  app_data_records_sizes: "
        + ", ".join(str(v) for v in obj.get("app_data_records_sizes", []))
    )
    lines.append(f"  total_app_data_len: {obj.get('total_app_data_len', '-')}")

    cert = obj.get("cert_info")
    if cert:
        lines.append("  cert_info:")
        lines.append(f"    subject_cn: {cert.get('subject_cn') or '-'}")
        lines.append(f"    issuer_cn: {cert.get('issuer_cn') or '-'}")
        lines.append(f"    not_before: {ts_to_iso(cert.get('not_before_unix'))}")
        lines.append(f"    not_after:  {ts_to_iso(cert.get('not_after_unix'))}")
        sans = cert.get("san_names") or []
        lines.append("    san_names: " + (", ".join(sans) if sans else "-"))
    else:
        lines.append("  cert_info: -")

    exts = sh.get("extensions", [])
    lines.append(f"  extensions[{len(exts)}]:")
    for ext in exts:
        ext_type = int(ext.get("ext_type", -1))
        data = ext.get("data", [])
        name = EXT_NAMES.get(ext_type, "unknown")
        decoded = decode_extension(ext_type, data)
        lines.append(
            f"    - type={ext_type} ({name}), len={len(data)}: {decoded}"
        )
    lines.append("")
    return "\n".join(lines)


def collect_files(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    return sorted(p for p in input_path.glob("*.json") if p.is_file())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode tlsfront profile JSON files into readable form."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="tlsfront",
        help="Path to tlsfront directory or a single JSON file.",
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

    for path in files:
        try:
            print(decode_profile(path), end="")
        except Exception as e:  # noqa: BLE001
            print(f"[{path.name}] decode error: {e}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
