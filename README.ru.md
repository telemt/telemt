# Telemt — MTProxy на Rust + Tokio

***Решает проблемы раньше, чем другие узнают об их существовании***

> [!NOTE]
>
> Исправленный TLS ClientHello доступен:
> - в **Telegram Desktop** начиная с версии **6.7.2**
> - в **Telegram Android** начиная с версии **12.6.4**
> - **официальный релиз для iOS находится в процессе разработки**.
>
> Для работы с EE-MTProxy обновите клиент!

<p align="center">
  <a href="https://t.me/telemtrs">
    <img src="/docs/assets/telegram_button.svg" width="200"/>
  </a>
</p>

**Telemt** — это быстрый, безопасный и функциональный сервер, написанный на Rust. Он полностью реализует официальный алгоритм прокси Telegram и добавляет множество улучшений для продакшена:
- [ME Pool + Reader/Writer + Registry + Refill + Adaptive Floor + Trio-State + жизненный цикл генераций](https://github.com/telemt/telemt/blob/main/docs/Architecture/Model/MODEL.en.md);
- [Полноценный API с управлением](https://github.com/telemt/telemt/blob/main/docs/Architecture/API/API.md);
- Защита от повторных атак (Anti-Replay on Sliding Window);
- Метрики в формате Prometheus;
- TLS-fronting и TCP-splicing для маскировки от DPI.

![telemt_scheme](docs/assets/telemt.png)

## Особенности
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


## Быстрая установка (обновление при повторном запуске)
```bash
curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh
```

Подробнее об установке в [Quick Start Guide](docs/Quick_start/QUICK_START_GUIDE.ru.md).

# Навигация
- [FAQ](#faq)
- [Архитектура](docs/Architecture)
- [Быстрый старт](#quick-start-guide)
- [Параметры конфигурационного файла](docs/Config_params)
- [Сборка](#build)
- [Почему Rust?](#why-rust)
- [Известные проблемы](#issues)
- [Планы](#roadmap)

## Быстрый старт
- [Quick Start Guide RU](docs/Quick_start/QUICK_START_GUIDE.ru.md)
- [Quick Start Guide EN](docs/Quick_start/QUICK_START_GUIDE.en.md)

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

### OpenBSD
- Руководство по сборке и настройке на английском языке [OpenBSD Guide (EN)](docs/Quick_start/OPENBSD_QUICK_START_GUIDE.en.md);
- Пример rc.d скрипта: [contrib/openbsd/telemt.rcd](contrib/openbsd/telemt.rcd);
- Поддержка sandbox с `pledge(2)` и `unveil(2)` пока не реализована.

## Почему Rust?
- Надёжность для долгоживущих процессов;
- Детерминированное управление ресурсами (RAII);
- Отсутствие сборщика мусора;
- Безопасность памяти;
- Асинхронная архитектура Tokio.
