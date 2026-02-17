"""Telegram datacenter server checker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from itertools import groupby
from operator import attrgetter
from pathlib import Path
from typing import TYPE_CHECKING

from telethon import TelegramClient
from telethon.tl.functions.help import GetConfigRequest

if TYPE_CHECKING:
    from telethon.tl.types import DcOption

API_ID: int = 123456
API_HASH: str = ""
SESSION_NAME: str = "session"
OUTPUT_FILE: Path = Path("telegram_servers.txt")

_CONSOLE_FLAG_MAP: dict[str, str] = {
    "IPv6": "IPv6",
    "MEDIA-ONLY": "🎬 MEDIA-ONLY",
    "CDN": "📦 CDN",
    "TCPO": "🔒 TCPO",
    "STATIC": "📌 STATIC",
}


@dataclass(frozen=True, slots=True)
class DCServer:
    """Typed representation of a Telegram DC server.

    Attributes:
        dc_id: Datacenter identifier.
        ip: Server IP address.
        port: Server port.
        flags: Active flag labels (plain, without emoji).
    """

    dc_id: int
    ip: str
    port: int
    flags: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_option(cls, dc: DcOption) -> DCServer:
        """Create from a Telethon DcOption.

        Args:
            dc: Raw DcOption object.

        Returns:
            Parsed DCServer instance.
        """
        checks: dict[str, bool] = {
            "IPv6": dc.ipv6,
            "MEDIA-ONLY": dc.media_only,
            "CDN": dc.cdn,
            "TCPO": dc.tcpo_only,
            "STATIC": dc.static,
        }
        return cls(
            dc_id=dc.id,
            ip=dc.ip_address,
            port=dc.port,
            flags=frozenset(k for k, v in checks.items() if v),
        )

    def flags_display(self, *, emoji: bool = False) -> str:
        """Formatted flags string.

        Args:
            emoji: Whether to include emoji prefixes.

        Returns:
            Bracketed flags or '[STANDARD]'.
        """
        if not self.flags:
            return "[STANDARD]"
        labels = sorted(
            _CONSOLE_FLAG_MAP[f] if emoji else f for f in self.flags
        )
        return f"[{', '.join(labels)}]"


class TelegramDCChecker:
    """Fetches and displays Telegram DC configuration.

    Attributes:
        _client: Telethon client instance.
        _servers: Parsed server list.
    """

    def __init__(self) -> None:
        """Initialize the checker."""
        self._client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
        self._servers: list[DCServer] = []

    async def run(self) -> None:
        """Connect, fetch config, display and save results."""
        print("🔄 Подключаемся к Telegram...")  # noqa: T201
        try:
            await self._client.start()
            print("✅ Подключение установлено!\n")  # noqa: T201

            print("📡 Запрашиваем конфигурацию серверов...")  # noqa: T201
            config = await self._client(GetConfigRequest())
            self._servers = [DCServer.from_option(dc) for dc in config.dc_options]

            self._print(config)
            self._save(config)
        finally:
            await self._client.disconnect()
            print("\n👋 Отключились от Telegram")  # noqa: T201

    def _grouped(self) -> dict[int, list[DCServer]]:
        """Group servers by DC ID.

        Returns:
            Ordered mapping of DC ID to servers.
        """
        ordered = sorted(self._servers, key=attrgetter("dc_id"))
        return {k: list(g) for k, g in groupby(ordered, key=attrgetter("dc_id"))}

    def _print(self, config: object) -> None:
        """Print results to stdout in original format.

        Args:
            config: Raw Telegram config.
        """
        sep = "=" * 80
        dash = "-" * 80
        total = len(self._servers)

        print(f"📊 Получено серверов: {total}\n")  # noqa: T201
        print(sep)  # noqa: T201

        for dc_id, servers in self._grouped().items():
            print(f"\n🌐 DATACENTER {dc_id} ({len(servers)} серверов)")  # noqa: T201
            print(dash)  # noqa: T201
            for s in servers:
                print(f"  {s.ip:45}:{s.port:5} {s.flags_display(emoji=True)}")  # noqa: T201

        ipv4 = total - self._flag_count("IPv6")
        print(f"\n{sep}")  # noqa: T201
        print("📈 СТАТИСТИКА:")  # noqa: T201
        print(sep)  # noqa: T201
        print(f"  Всего серверов:      {total}")  # noqa: T201
        print(f"  IPv4 серверы:        {ipv4}")  # noqa: T201
        print(f"  IPv6 серверы:        {self._flag_count('IPv6')}")  # noqa: T201
        print(f"  Media-only:          {self._flag_count('MEDIA-ONLY')}")  # noqa: T201
        print(f"  CDN серверы:         {self._flag_count('CDN')}")  # noqa: T201
        print(f"  TCPO-only:           {self._flag_count('TCPO')}")  # noqa: T201
        print(f"  Static:              {self._flag_count('STATIC')}")  # noqa: T201

        print(f"\n{sep}")  # noqa: T201
        print("ℹ️  ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ:")  # noqa: T201
        print(sep)  # noqa: T201
        print(f"  Дата конфигурации:   {config.date}")  # noqa: T201  # type: ignore[attr-defined]
        print(f"  Expires:             {config.expires}")  # noqa: T201  # type: ignore[attr-defined]
        print(f"  Test mode:           {config.test_mode}")  # noqa: T201  # type: ignore[attr-defined]
        print(f"  This DC:             {config.this_dc}")  # noqa: T201  # type: ignore[attr-defined]

    def _flag_count(self, flag: str) -> int:
        """Count servers with a given flag.

        Args:
            flag: Flag name.

        Returns:
            Count of matching servers.
        """
        return sum(1 for s in self._servers if flag in s.flags)

    def _save(self, config: object) -> None:
        """Save results to file in original format.

        Args:
            config: Raw Telegram config.
        """
        parts: list[str] = []
        parts.append("TELEGRAM DATACENTER SERVERS\n")
        parts.append("=" * 80 + "\n\n")

        for dc_id, servers in self._grouped().items():
            parts.append(f"\nDATACENTER {dc_id} ({len(servers)} servers)\n")
            parts.append("-" * 80 + "\n")
            for s in servers:
                parts.append(f"  {s.ip}:{s.port} {s.flags_display(emoji=False)}\n")

        parts.append(f"\n\nTotal servers: {len(self._servers)}\n")
        parts.append(f"Generated: {config.date}\n")  # type: ignore[attr-defined]

        OUTPUT_FILE.write_text("".join(parts), encoding="utf-8")

        print(f"\n💾 Сохраняем результаты в файл {OUTPUT_FILE}...")  # noqa: T201
        print(f"✅ Результаты сохранены в {OUTPUT_FILE}")  # noqa: T201


if __name__ == "__main__":
    asyncio.run(TelegramDCChecker().run())
