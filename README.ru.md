# Telemt — MTProxy на Rust + Tokio

[![Latest Release](https://img.shields.io/github/v/release/telemt/telemt?color=neon)](https://github.com/telemt/telemt/releases/latest) [![Stars](https://img.shields.io/github/stars/telemt/telemt?style=social)](https://github.com/telemt/telemt/stargazers) [![Forks](https://img.shields.io/github/forks/telemt/telemt?style=social)](https://github.com/telemt/telemt/network/members)

> [!NOTE]
>
> Клиенты Telegram подвергаются блокировке по JA3-отпечатку; мы ищем варианты решения этой проблемы
> 
> Вы можете попробовать собрать свой клиент с нашей Telegram Devlibrary — [tdlib-obf](https://github.com/telemt/tdlib-obf)

<p align="center">
  <a href="https://t.me/telemtrs">
    <img src="https://github.com/user-attachments/assets/30b7e7b9-974a-4e3d-aab6-b58a85de4507" width="240"/>
  </a>
</p>

**Telemt** — это быстрый, безопасный и функциональный сервер, написанный на Rust: он полностью реализует официальный алгоритм Telegram прокси и добавляет множество различных улучшений

## Установка и обновление одной командой

```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh
```
- [Инструкция по быстрому запуску](docs/Quick_start/QUICK_START_GUIDE.ru.md)

## Функционал
Наша реализация **TLS-fronting** одна из наиболее глубоко отлаженных, продвинутых и почти поведенчески неотличима от настоящего: мы уверены, что сделали это правильно - [см. доказательства в нашей проверке](docs/FAQ.ru.md#распознаваемость-для-dpi-и-сканеров).

Наша архитектура ***Middle-End Pool*** в стандартных сценариях самая производительная, по сравнению с другими реализациями подключения к Middle-End прокси: не кардинально, но достаточно

- Полная поддержа всех официальных режимов MTProto proxy:
  - Classic;
  - Secure — с префиксом `dd`;
  - Fake TLS — с префиксом `ee` + SNI fronting;
- Защита от replay-атак;
- Опциональная маскировка трафика: перенаправление неизвестных подключений на реальные сайты;
- Настраиваемые keepalive, таймауты, IPv6 и "быстрый режим";
- Корректное завершение работы (Ctrl+C);
- Подробное логирование через `trace` и `debug` с помощью `RUST_LOG`.

## ЧаВо
- [Часто задаваемые вопросы](docs/FAQ.ru.md)

# Узнайте больше о Telemt
- [Наша архитектура](docs/Architecture)
- [Все конфигурационные параметры](docs/Config_params)
- [Как собрать Telemt самостоятельно?](#сборка)
- [Установка на BSD](docs/Quick_start/OPENBSD_QUICK_START_GUIDE.en.md)
- [Почему Rust?](#почему-rust)

## Сборка
```bash
# Клонируйте репозиторий
git clone https://github.com/telemt/telemt 
# Смените каталог на telemt
cd telemt
# Начните процесс сборки
cargo build --release

# В текущем release-профиле используется lto = "fat" для максимальной оптимизации (см. Cargo.toml).
# На системах с малым объёмом ОЗУ (~1 ГБ) можно переопределить это значение на "thin".

# Перейдите в каталог /bin
mv ./target/release/telemt /bin
# Сделайте файл исполняемым
chmod +x /bin/telemt
# Запустите!
telemt config.toml
```

## Почему Rust?
- Надёжность при длительной работе и идемпотентное поведение;
- Детерминированное управление ресурсами — RAII;
- Отсутствие сборщика мусора;
- Безопасность памяти и меньше поверхность атаки;
- Асинхронная архитектура Tokio.

## Поддержать Telemt

Telemt — это бесплатное программное обеспечение с открытым исходным кодом, разрабатываемое в свободное время.
Если оно оказалось вам полезным, вы можете поддержать дальнейшую разработку.

Любая криптовалюта (BTC, ETH, USDT и 350+ других):

<p align="center">
  <a href="https://nowpayments.io/donation?api_key=2bf1afd2-abc2-49f9-a012-f1e715b37223" target="_blank" rel="noreferrer noopener">
    <img src="https://nowpayments.io/images/embeds/donation-button-white.svg" alt="Cryptocurrency & Bitcoin donation button by NOWPayments" height="80">
  </a>
</p>

Monero (XMR) напрямую:

```
8Bk4tZEYPQWSypeD2hrUXG2rKbAKF16GqEN942ZdAP5cFdSqW6h4DwkP5cJMAdszzuPeHeHZPTyjWWFwzeFdjuci3ktfMoB
```

Все пожертвования пойдут на инфраструктуру, разработку и исследования.

![telemt_scheme](docs/assets/telemt.png)
