# Telemt — MTProxy на Rust + Tokio

![Latest Release](https://img.shields.io/github/v/release/telemt/telemt?color=neon) ![Stars](https://img.shields.io/github/stars/telemt/telemt?style=social) ![Forks](https://img.shields.io/github/forks/telemt/telemt?style=social) [![Telegram](https://img.shields.io/badge/Telegram-Chat-24a1de?logo=telegram&logoColor=24a1de)](https://t.me/telemtrs)

***Решает проблемы раньше, чем другие узнают об их существовании***

> [!NOTE]
>
> Исправленный TLS ClientHello доступен в Telegram для настольных ПК, Android и iOS.
> 
> Пожалуйста, обновите клиентское приложение для работы с EE-MTProxy.

<p align="center">
  <a href="https://t.me/telemtrs">
    <img src="/docs/assets/telegram_button.svg" width="150"/>
  </a>
</p>

**Telemt** — это быстрый, безопасный и функциональный сервер, написанный на Rust. Он полностью реализует официальный алгоритм прокси Telegram и добавляет множество улучшений для продакшена:

## Установка и обновление одной командой

```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh
```

- [Инструкция по быстрому запуску](docs/Quick_start/QUICK_START_GUIDE.ru.md)
- [Quick Start Guide](docs/Quick_start/QUICK_START_GUIDE.en.md)

Реализация **TLS-fronting** максимально приближена к поведению реального HTTPS-трафика (подробнее - [FAQ](docs/FAQ.ru.md#распознаваемость-для-dpi-и-сканеров)).

***Middle-End Pool*** оптимизирован для высокой производительности.

- Поддержка всех режимов MTProto proxy:
  - Classic;
  - Secure (префикс `dd`);
  - Fake TLS (префикс `ee` + SNI fronting);
- Защита от replay-атак;
- Маскировка трафика (перенаправление неизвестных подключений на реальные сайты);
- Настраиваемые keepalive, таймауты, IPv6 и «быстрый режим»;
- Корректное завершение работы (Ctrl+C);
- Подробное логирование через `trace` и `debug`.

# Подробнее о Telemt
- [FAQ](#faq)
- [Архитектура](docs/Architecture)
- [Параметры конфигурационного файла](docs/Config_params)
- [Сборка](#build)
- [Установка на BSD](#%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%B0-%D0%BD%D0%B0-bsd)
- [Почему Rust?](#why-rust)

## FAQ
- [FAQ RU](docs/FAQ.ru.md)
- [FAQ EN](docs/FAQ.en.md)

## Сборка
```bash
# Клонируйте репозиторий
git clone https://github.com/telemt/telemt 
# Смените каталог на telemt
cd telemt
# Начните процесс сборки
cargo build --release

# В текущем release-профиле используется lto = "fat" для максимальной оптимизации (см. Cargo.toml).
# На системах с малым объёмом RAM (~1 ГБ) можно переопределить это значение на "thin".

# Перейдите в каталог /bin
mv ./target/release/telemt /bin
# Сделайте файл исполняемым
chmod +x /bin/telemt
# Запустите!
telemt config.toml
```

## Установка на BSD
- Руководство по сборке и настройке на английском языке [OpenBSD Guide (EN)](docs/Quick_start/OPENBSD_QUICK_START_GUIDE.en.md);
- Пример rc.d скрипта: [contrib/openbsd/telemt.rcd](contrib/openbsd/telemt.rcd);
- Поддержка sandbox с `pledge(2)` и `unveil(2)` пока не реализована.

## Почему Rust?
- Надёжность для долгоживущих процессов;
- Детерминированное управление ресурсами (RAII);
- Отсутствие сборщика мусора;
- Безопасность памяти;
- Асинхронная архитектура Tokio.

![telemt_scheme](docs/assets/telemt.png)
