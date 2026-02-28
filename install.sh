sudo bash -c '
set -e

# --- Проверка на существующую установку ---
if systemctl list-unit-files | grep -q telemt.service; then
    # --- РЕЖИМ ОБНОВЛЕНИЯ ---
    echo "--- Обнаружена существующая установка Telemt. Запускаю обновление... ---"

    echo "[*] Остановка службы telemt..."
    systemctl stop telemt || true # Игнорируем ошибку, если служба уже остановлена

    echo "[1/2] Скачивание последней версии Telemt..."
    wget -qO- "https://github.com/telemt/telemt/releases/latest/download/telemt-$(uname -m)-linux-$(ldd --version 2>&1 | grep -iq musl && echo musl || echo gnu).tar.gz" | tar -xz

    echo "[1/2] Замена исполняемого файла в /usr/local/bin..."
    mv telemt /usr/local/bin/telemt
    chmod +x /usr/local/bin/telemt

    echo "[2/2] Запуск службы..."
    systemctl start telemt

    echo "--- Обновление Telemt успешно завершено! ---"
    echo
    echo "Для проверки статуса службы выполните:"
    echo "   systemctl status telemt"

else
    # --- РЕЖИМ НОВОЙ УСТАНОВКИ ---
    echo "--- Начало автоматической установки Telemt ---"

    # Шаг 1: Скачивание и установка бинарного файла
    echo "[1/5] Скачивание последней версии Telemt..."
    wget -qO- "https://github.com/telemt/telemt/releases/latest/download/telemt-$(uname -m)-linux-$(ldd --version 2>&1 | grep -iq musl && echo musl || echo gnu).tar.gz" | tar -xz

    echo "[1/5] Перемещение исполняемого файла в /usr/local/bin и установка прав..."
    mv telemt /usr/local/bin/telemt
    chmod +x /usr/local/bin/telemt

    # Шаг 2: Генерация секрета
    echo "[2/5] Генерация секретного ключа..."
    SECRET=$(openssl rand -hex 16)

    # Шаг 3: Создание файла конфигурации
    echo "[3/5] Создание файла конфигурации /etc/telemt.toml..."
    printf "# === General Settings ===\n[general]\n[general.modes]\nclassic = false\nsecure = false\ntls = true\n\n# === Anti-Censorship & Masking ===\n[censorship]\n# !!! ВАЖНО: Замените на ваш домен или домен, который вы хотите использовать для маскировки !!!\ntls_domain = \"petrovich.ru\"\n\n[access.users]\nhello = \"%s\"\n" "$SECRET" > /etc/telemt.toml

    # Шаг 4: Создание службы Systemd
    echo "[4/5] Создание службы systemd..."
    printf "[Unit]\nDescription=Telemt Proxy\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/telemt /etc/telemt.toml\nRestart=on-failure\nRestartSec=5\nLimitNOFILE=65536\n\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/telemt.service

    # Шаг 5: Запуск службы
    echo "[5/5] Перезагрузка systemd, запуск и включение службы telemt..."
    systemctl daemon-reload
    systemctl start telemt
    systemctl enable telemt

    echo "--- Установка и запуск Telemt успешно завершены! ---"
    echo
    echo "ВАЖНАЯ ИНФОРМАЦИЯ:"
    echo "==================="
    echo "1. Вам НЕОБХОДИМО отредактировать файл /etc/telemt.toml и заменить '\''petrovich.ru'\'' на другой домен"
    echo "   с помощью команды:"
    echo "   nano /etc/telemt.toml"
    echo "   После редактирования файла перезапустите службу командой:"
    echo "   sudo systemctl restart telemt"
    echo
    echo "2. Для проверки статуса службы выполните команду:"
    echo "   systemctl status telemt"
    echo
    echo "3. Для получения ссылок на подключение выполните команду:"
    echo "   journalctl -u telemt -n -g '\''links'\'' --no-pager -o cat | tac"
fi
'
