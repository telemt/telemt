#!/bin/sh
set -eu

REPO="${REPO:-Gickrede-e/telemt_bb}"
# When release artifacts are missing (or BUILD_FROM_SOURCE=1) the script
# falls back to git clone + cargo build --release of the requested branch.
BRANCH="${BRANCH:-main}"
BUILD_FROM_SOURCE="${BUILD_FROM_SOURCE:-0}"
BIN_NAME="${BIN_NAME:-telemt}"
INSTALL_DIR="${INSTALL_DIR:-/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/telemt}"
CONFIG_FILE="${CONFIG_FILE:-${CONFIG_DIR}/telemt.toml}"
WORK_DIR="${WORK_DIR:-/opt/telemt}"
TLS_DOMAIN="${TLS_DOMAIN:-petrovich.ru}"
SERVER_PORT="${SERVER_PORT:-443}"
USER_SECRET=""
AD_TAG=""
SERVICE_NAME="telemt"
TEMP_DIR=""
SUDO=""
CONFIG_PARENT_DIR=""
SERVICE_START_FAILED=0

PORT_PROVIDED=0
SECRET_PROVIDED=0
AD_TAG_PROVIDED=0
DOMAIN_PROVIDED=0
LANG_PROVIDED=0

ACTION="install"
TARGET_VERSION="${VERSION:-latest}"
LANG_CHOICE="en"

PATH="${PATH}:/usr/sbin:/sbin"

set_language() {
    case "$1" in
        ru)
            L_ERR_DOMAIN_REQ="требует аргумент (домен)."
            L_ERR_PORT_REQ="требует аргумент (порт)."
            L_ERR_PORT_NUM="Порт должен быть числом."
            L_ERR_PORT_RANGE="Порт должен быть от 1 до 65535."
            L_ERR_SECRET_REQ="требует аргумент (секрет)."
            L_ERR_SECRET_HEX="Секрет должен содержать только HEX символы."
            L_ERR_SECRET_LEN="Секрет должен состоять ровно из 32 символов."
            L_ERR_ADTAG_REQ="требует аргумент (ad_tag)."
            L_ERR_UNKNOWN_OPT="Неизвестная опция:"
            L_WARN_EXTRA_ARG="Игнорируется лишний аргумент:"
            L_ERR_REQ_ARG="требует аргумент (1, 2, en или ru)."
            L_ERR_EMPTY_VAR="не может быть пустым."
            L_ERR_INV_VER="Недопустимые символы в версии."
            L_ERR_INV_BIN="Недопустимые символы в BIN_NAME."
            L_ERR_ROOT="Для работы скрипта требуются права root или sudo."
            L_ERR_SUDO_TTY="sudo требует пароль, но терминал (TTY) не обнаружен."
            L_ERR_DIR_CHECK="Ошибка: конфиг является директорией."
            L_ERR_CMD_NOT_FOUND="Необходимая команда не найдена:"
            L_ERR_NO_DL_TOOL="Не установлен curl или wget."
            L_ERR_NO_CP_TOOL="Необходима утилита cp или install."
            L_WARN_NO_NET_TOOL="Утилиты сети не найдены. Проверка порта пропущена."
            L_INFO_PORT_IGNORE="Порт занят текущим процессом телеметрии. Игнорируем."
            L_ERR_PORT_IN_USE="Порт уже занят другим процессом:"
            L_ERR_PORT_FREE="Освободите порт или укажите другой и попробуйте снова."
            L_ERR_UNSUP_ARCH="Неподдерживаемая архитектура:"
            L_ERR_CREATE_GRP="Не удалось создать группу"
            L_ERR_CREATE_USR="Не удалось создать пользователя"
            L_ERR_MKDIR="Не удалось создать директории"
            L_ERR_INSTALL_DIR="не является директорией."
            L_ERR_BIN_INSTALL="Не удалось установить бинарный файл"
            L_ERR_BIN_COPY="Не удалось скопировать бинарный файл"
            L_ERR_BIN_EXEC="Бинарный файл не исполняемый."
            L_ERR_GEN_SEC="Не удалось сгенерировать секрет."
            L_INFO_CONF_EXISTS="Конфиг уже существует. Обновление параметров..."
            L_INFO_UPD_PORT="Обновлен порт:"
            L_INFO_UPD_SEC="Обновлен секрет для пользователя 'hello'"
            L_INFO_UPD_DOM="Обновлен tls_domain:"
            L_INFO_UPD_TAG="Обновлен ad_tag"
            L_ERR_CONF_INST="Не удалось установить конфиг"
            L_INFO_CONF_OK="Конфиг успешно создан."
            L_INFO_CONF_SEC="Настроен секрет для пользователя 'hello':"
            L_WARN_SVC_FAIL="Не удалось запустить службу"
            L_INFO_MANUAL_START="Менеджер служб не найден. Запустите вручную:"
            L_INFO_UNINST_START="Начинается удаление"
            L_U_STAGE_1=">>> Этап 1: Остановка служб"
            L_U_STAGE_2=">>> Этап 2: Удаление конфигурации службы"
            L_U_STAGE_3=">>> Этап 3: Завершение процессов пользователя"
            L_U_STAGE_4=">>> Этап 4: Удаление бинарного файла"
            L_U_STAGE_5=">>> Этап 5: Полная очистка (конфиг, данные, пользователь)"
            L_INFO_KEEP_CONF="Примечание: Конфигурация сохранена. Используйте 'purge' для очистки."
            L_INFO_I_START="Начинается установка"
            L_I_STAGE_1=">>> Этап 1: Проверка окружения и зависимостей"
            L_I_STAGE_1_5=">>> Этап 1.5: Интерактивная настройка"
            L_I_PROMPT_DOM="\nПожалуйста, укажите домен TLS\nНажмите Enter, чтобы оставить по умолчанию [%s]: "
            L_WARN_NO_TTY="Интерактивный режим недоступен (нет TTY). Используется:"
            L_I_STAGE_2=">>> Этап 2: Загрузка архива"
            L_ERR_TMP_DIR="Не удалось создать временную директорию"
            L_ERR_TMP_INV="Временная директория недействительна"
            L_INFO_FALLBACK="Сборка x86_64-v3 не найдена, откат к стандартной x86_64..."
            L_ERR_DL_FAIL="Ошибка загрузки архива"
            L_INFO_BUILD_FALLBACK="Релизный архив недоступен, переходим к сборке из исходников (ветка %s)..."
            L_I_BUILD_START=">>> Этап 2b: git clone + cargo build --release (это может занять несколько минут)"
            L_ERR_NO_GIT="Для сборки из исходников необходим git. Установите его и повторите запуск."
            L_ERR_NO_CARGO="Для сборки из исходников необходим cargo (Rust toolchain). Установите Rust через https://rustup.rs/ и повторите запуск."
            L_ERR_CLONE_FAIL="Не удалось клонировать репозиторий %s (ветка %s)."
            L_ERR_BUILD_FAIL="cargo build --release завершился ошибкой."
            L_ERR_BUILT_BIN_MISSING="После сборки не найден ожидаемый бинарь target/release/%s."
            L_I_STAGE_3=">>> Этап 3: Распаковка архива"
            L_ERR_EXTRACT="Ошибка распаковки архива."
            L_ERR_BIN_NOT_FOUND="Бинарный файл не найден в архиве"
            L_I_STAGE_4=">>> Этап 4: Настройка окружения (Юзер, Группа, Папки)"
            L_I_STAGE_5=">>> Этап 5: Установка бинарного файла"
            L_I_STAGE_6=">>> Этап 6: Генерация/Обновление конфигурации"
            L_I_STAGE_7=">>> Этап 7: Установка и запуск службы"
            L_OUT_WARN_H="УСТАНОВКА ЗАВЕРШЕНА С ПРЕДУПРЕЖДЕНИЯМИ"
            L_OUT_WARN_D="Служба установлена, но не запустилась.\nПожалуйста, проверьте логи.\n"
            L_OUT_SUCC_H="УСТАНОВКА УСПЕШНО ЗАВЕРШЕНА"
            L_OUT_UNINST_H="УДАЛЕНИЕ ЗАВЕРШЕНО"
            L_OUT_LINK="Ваша ссылка для подключения к Telegram Proxy:\n"
            L_ERR_INCORR_ROOT_LOGIN="Используйте 'su -' или 'sudo -i' для входа под пользователем root"
            L_OUT_LOGS="Чтобы посмотреть логи (в случае проблем), используйте команду:"
            ;;
        *)
            L_ERR_DOMAIN_REQ="requires a domain argument."
            L_ERR_PORT_REQ="requires a port argument."
            L_ERR_PORT_NUM="Port must be a valid number."
            L_ERR_PORT_RANGE="Port must be between 1 and 65535."
            L_ERR_SECRET_REQ="requires a secret argument."
            L_ERR_SECRET_HEX="Secret must contain only hex characters."
            L_ERR_SECRET_LEN="Secret must be exactly 32 chars."
            L_ERR_ADTAG_REQ="requires an ad_tag argument."
            L_ERR_UNKNOWN_OPT="Unknown option:"
            L_WARN_EXTRA_ARG="Ignoring extra argument:"
            L_ERR_REQ_ARG="requires an argument (1, 2, en, ru)."
            L_ERR_EMPTY_VAR="cannot be empty."
            L_ERR_INV_VER="Invalid characters in version."
            L_ERR_INV_BIN="Invalid characters in BIN_NAME."
            L_ERR_ROOT="This script requires root or sudo."
            L_ERR_SUDO_TTY="sudo requires a password, but no TTY detected."
            L_ERR_DIR_CHECK="Safety check failed: Config is a directory."
            L_ERR_CMD_NOT_FOUND="Required command not found:"
            L_ERR_NO_DL_TOOL="Neither curl nor wget is installed."
            L_ERR_NO_CP_TOOL="Need cp or install."
            L_WARN_NO_NET_TOOL="Network tools not found. Skipping port check."
            L_INFO_PORT_IGNORE="Port is in use by telemt. Ignoring as it will be restarted."
            L_ERR_PORT_IN_USE="Port is already in use by another process:"
            L_ERR_PORT_FREE="Please free the port or change it and try again."
            L_ERR_UNSUP_ARCH="Unsupported architecture:"
            L_ERR_CREATE_GRP="Cannot create group"
            L_ERR_CREATE_USR="Cannot create user"
            L_ERR_MKDIR="Failed to create directories"
            L_ERR_INSTALL_DIR="is not a directory."
            L_ERR_BIN_INSTALL="Failed to install binary"
            L_ERR_BIN_COPY="Failed to copy binary"
            L_ERR_BIN_EXEC="Binary not executable."
            L_ERR_GEN_SEC="Failed to generate secret."
            L_INFO_CONF_EXISTS="Config already exists. Updating parameters..."
            L_INFO_UPD_PORT="Updated port:"
            L_INFO_UPD_SEC="Updated secret for user 'hello'"
            L_INFO_UPD_DOM="Updated tls_domain:"
            L_INFO_UPD_TAG="Updated ad_tag"
            L_ERR_CONF_INST="Failed to install config"
            L_INFO_CONF_OK="Config created successfully."
            L_INFO_CONF_SEC="Configured secret for user 'hello':"
            L_WARN_SVC_FAIL="Failed to start service"
            L_INFO_MANUAL_START="Service manager not found. Start manually:"
            L_INFO_UNINST_START="Starting uninstallation of"
            L_U_STAGE_1=">>> Stage 1: Stopping services"
            L_U_STAGE_2=">>> Stage 2: Removing service configuration"
            L_U_STAGE_3=">>> Stage 3: Terminating user processes"
            L_U_STAGE_4=">>> Stage 4: Removing binary"
            L_U_STAGE_5=">>> Stage 5: Purging configuration, data, and user"
            L_INFO_KEEP_CONF="Note: Configuration kept. Run with 'purge' to remove completely."
            L_INFO_I_START="Starting installation of"
            L_I_STAGE_1=">>> Stage 1: Verifying environment and dependencies"
            L_I_STAGE_1_5=">>> Stage 1.5: Interactive Setup"
            L_I_PROMPT_DOM="\nPlease specify the TLS Domain\nPress Enter to keep default [%s]: "
            L_WARN_NO_TTY="Interactive mode unavailable (no TTY). Using:"
            L_I_STAGE_2=">>> Stage 2: Downloading archive"
            L_ERR_TMP_DIR="Temp directory creation failed"
            L_ERR_TMP_INV="Temp directory is invalid or was not created"
            L_INFO_FALLBACK="x86_64-v3 build not found, falling back to standard x86_64..."
            L_ERR_DL_FAIL="Download failed"
            L_INFO_BUILD_FALLBACK="Release artifact unavailable, falling back to building from source (branch %s)..."
            L_I_BUILD_START=">>> Stage 2b: git clone + cargo build --release (this can take a few minutes)"
            L_ERR_NO_GIT="Building from source requires git. Install it and re-run."
            L_ERR_NO_CARGO="Building from source requires cargo (Rust toolchain). Install Rust via https://rustup.rs/ and re-run."
            L_ERR_CLONE_FAIL="Failed to clone repository %s (branch %s)."
            L_ERR_BUILD_FAIL="cargo build --release failed."
            L_ERR_BUILT_BIN_MISSING="Built binary target/release/%s not found after build."
            L_I_STAGE_3=">>> Stage 3: Extracting archive"
            L_ERR_EXTRACT="Extraction failed."
            L_ERR_BIN_NOT_FOUND="Binary not found in archive"
            L_I_STAGE_4=">>> Stage 4: Setting up environment (User, Group, Directories)"
            L_I_STAGE_5=">>> Stage 5: Installing binary"
            L_I_STAGE_6=">>> Stage 6: Generating/Updating configuration"
            L_I_STAGE_7=">>> Stage 7: Installing and starting service"
            L_OUT_WARN_H="INSTALLATION COMPLETED WITH WARNINGS"
            L_OUT_WARN_D="The service was installed but failed to start.\nPlease check the logs to determine the issue.\n"
            L_OUT_SUCC_H="INSTALLATION SUCCESS"
            L_OUT_UNINST_H="UNINSTALLATION COMPLETE"
            L_OUT_LINK="Your Telegram Proxy connection link:\n"
            L_ERR_INCORR_ROOT_LOGIN="Use 'su -' or 'sudo -i' to login under root"
            L_OUT_LOGS="To view logs (in case of issues), use the following command:"
            ;;
    esac
}

set_language "$LANG_CHOICE"

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) ACTION="help"; shift ;;
        -l|--lang)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf '[ERROR] %s %s\n' "$1" "$L_ERR_REQ_ARG" >&2; exit 1
            fi
            case "$2" in
                ru|2) LANG_CHOICE="ru"; set_language "$LANG_CHOICE"; LANG_PROVIDED=1 ;;
                en|1) LANG_CHOICE="en"; set_language "$LANG_CHOICE"; LANG_PROVIDED=1 ;;
                *) printf '[ERROR] %s %s\n' "$1" "$L_ERR_REQ_ARG" >&2; exit 1 ;;
            esac
            shift 2 ;;
        -d|--domain)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf '[ERROR] %s %s\n' "$1" "$L_ERR_DOMAIN_REQ" >&2; exit 1
            fi
            TLS_DOMAIN="$2"; DOMAIN_PROVIDED=1; shift 2 ;;
        -p|--port)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf '[ERROR] %s %s\n' "$1" "$L_ERR_PORT_REQ" >&2; exit 1
            fi
            case "$2" in
                *[!0-9]*) printf '[ERROR] %s\n' "$L_ERR_PORT_NUM" >&2; exit 1 ;;
            esac
            port_num="$(printf '%s\n' "$2" | sed 's/^0*//')"
            [ -z "$port_num" ] && port_num="0"
            if [ "${#port_num}" -gt 5 ] || [ "$port_num" -lt 1 ] || [ "$port_num" -gt 65535 ]; then
                printf '[ERROR] %s\n' "$L_ERR_PORT_RANGE" >&2; exit 1
            fi
            SERVER_PORT="$port_num"; PORT_PROVIDED=1; shift 2 ;;
        -s|--secret)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf '[ERROR] %s %s\n' "$1" "$L_ERR_SECRET_REQ" >&2; exit 1
            fi
            case "$2" in
                *[!0-9a-fA-F]*) printf '[ERROR] %s\n' "$L_ERR_SECRET_HEX" >&2; exit 1 ;;
            esac
            if [ "${#2}" -ne 32 ]; then
                printf '[ERROR] %s\n' "$L_ERR_SECRET_LEN" >&2; exit 1
            fi
            USER_SECRET="$2"; SECRET_PROVIDED=1; shift 2 ;;
        -a|--ad-tag|--ad_tag)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf '[ERROR] %s %s\n' "$1" "$L_ERR_ADTAG_REQ" >&2; exit 1
            fi
            AD_TAG="$2"; AD_TAG_PROVIDED=1; shift 2 ;;
        uninstall|--uninstall)
            if [ "$ACTION" != "purge" ]; then ACTION="uninstall"; fi
            shift ;;
        purge|--purge) ACTION="purge"; shift ;;
        install|--install) ACTION="install"; shift ;;
        -*) printf '[ERROR] %s %s\n' "$L_ERR_UNKNOWN_OPT" "$1" >&2; exit 1 ;;
        *)
            if [ "$ACTION" = "install" ]; then TARGET_VERSION="$1"
            else printf '[WARNING] %s %s\n' "$L_WARN_EXTRA_ARG" "$1" >&2; fi
            shift ;;
    esac
done

if [ "$ACTION" != "help" ] && [ "$LANG_PROVIDED" -eq 0 ]; then
    if [ -t 0 ] || [ -c /dev/tty ]; then
        printf "\nSelect language / Выберите язык:\n"
        printf "  1) English (default)\n"
        printf "  2) Русский\n"
        printf "Your choice / Ваш выбор [1/2]: "
        read -r input_lang </dev/tty || input_lang=""
        case "$input_lang" in
            2) LANG_CHOICE="ru" ;;
            *) LANG_CHOICE="en" ;;
        esac
    else
        LANG_CHOICE="en"
    fi
    set_language "$LANG_CHOICE"
fi

say() {
    if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
        printf '\n'
    else
        printf '[INFO] %s\n' "$*"
    fi
}
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

write_root() { $SUDO sh -c 'cat > "$1"' _ "$1"; }

cleanup() {
    if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf -- "$TEMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

show_help() {
    if [ "$LANG_CHOICE" = "ru" ]; then
        say "Использование: $0 [ <версия> | install | uninstall | purge ] [ опции ]"
        say "  <версия>     Установить конкретную версию (например, 3.3.15, по умолчанию: latest)"
        say "  install      Установить последнюю версию"
        say "  uninstall    Удалить бинарный файл и службу"
        say "  purge        Полностью удалить вместе с конфигурацией, данными и пользователем"
        say ""
        say "Опции:"
        say "  -d, --domain Указать домен TLS (по умолчанию: petrovich.ru)"
        say "  -p, --port   Указать порт сервера (по умолчанию: 443)"
        say "  -s, --secret Указать секрет пользователя (32 hex символа)"
        say "  -a, --ad-tag Указать ad_tag"
        say "  -l, --lang   Выбрать язык вывода (1/en или 2/ru)"
        say ""
        say "Переменные окружения:"
        say "  REPO=owner/repo            Источник релизов/исходников (по умолчанию: ${REPO})"
        say "  BRANCH=name                Ветка для сборки при fallback (по умолчанию: ${BRANCH})"
        say "  BUILD_FROM_SOURCE=1        Пропустить попытку скачивания, сразу собрать (требует git и cargo)"
        say "  INSTALL_DIR, CONFIG_DIR    Куда установить бинарь и конфиг"
    else
        say "Usage: $0 [ <version> | install | uninstall | purge ] [ options ]"
        say "  <version>    Install specific version (e.g. 3.3.15, default: latest)"
        say "  install      Install the latest version"
        say "  uninstall    Remove the binary and service"
        say "  purge        Remove everything including configuration, data, and user"
        say ""
        say "Options:"
        say "  -d, --domain Set TLS domain (default: petrovich.ru)"
        say "  -p, --port   Set server port (default: 443)"
        say "  -s, --secret Set specific user secret (32 hex characters)"
        say "  -a, --ad-tag Set ad_tag"
        say "  -l, --lang   Set output language (1/en or 2/ru)"
        say ""
        say "Environment variables:"
        say "  REPO=owner/repo            Release/source repository (default: ${REPO})"
        say "  BRANCH=name                Branch used by the build fallback (default: ${BRANCH})"
        say "  BUILD_FROM_SOURCE=1        Skip download and build from source (requires git and cargo)"
        say "  INSTALL_DIR, CONFIG_DIR    Where to install the binary and config"
    fi
    exit 0
}

check_os_entity() {
    if command -v getent >/dev/null 2>&1; then getent "$1" "$2" >/dev/null 2>&1
    else grep -q "^${2}:" "/etc/$1" 2>/dev/null; fi
}

normalize_path() {
    printf '%s\n' "$1" | tr -s '/' | sed 's|/$||; s|^$|/|'
}

get_realpath() {
    path_in="$1"
    case "$path_in" in /*) ;; *) path_in="$(pwd)/$path_in" ;; esac

    if command -v realpath >/dev/null 2>&1; then
        if realpath_out="$(realpath -m "$path_in" 2>/dev/null)"; then
            printf '%s\n' "$realpath_out"
            return
        fi
    fi

    if command -v readlink >/dev/null 2>&1; then
        resolved_path="$(readlink -f "$path_in" 2>/dev/null || true)"
        if [ -n "$resolved_path" ]; then
            printf '%s\n' "$resolved_path"
            return
        fi
    fi

    d="${path_in%/*}"; b="${path_in##*/}"
    if [ -z "$d" ]; then d="/"; fi
    if [ "$d" = "$path_in" ]; then d="/"; b="$path_in"; fi

    if [ -d "$d" ]; then
        abs_d="$(cd "$d" >/dev/null 2>&1 && pwd || true)"
        if [ -n "$abs_d" ]; then
            if [ "$b" = "." ] || [ -z "$b" ]; then printf '%s\n' "$abs_d"
            elif [ "$abs_d" = "/" ]; then printf '/%s\n' "$b"
            else printf '%s/%s\n' "$abs_d" "$b"; fi
        else
            normalize_path "$path_in"
        fi
    else
        normalize_path "$path_in"
    fi
}

get_svc_mgr() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then echo "systemd"
    elif command -v rc-service >/dev/null 2>&1; then echo "openrc"
    else echo "none"; fi
}

is_config_exists() {
    if [ -n "$SUDO" ]; then
        $SUDO sh -c '[ -f "$1" ]' _ "$CONFIG_FILE"
    else
        [ -f "$CONFIG_FILE" ]
    fi
}

verify_common() {
    [ -n "$BIN_NAME" ] || die "BIN_NAME $L_ERR_EMPTY_VAR"
    [ -n "$INSTALL_DIR" ] || die "INSTALL_DIR $L_ERR_EMPTY_VAR"
    [ -n "$CONFIG_DIR" ] || die "CONFIG_DIR $L_ERR_EMPTY_VAR"
    [ -n "$CONFIG_FILE" ] || die "CONFIG_FILE $L_ERR_EMPTY_VAR"

    case "$TARGET_VERSION" in *[!a-zA-Z0-9_.-]*) die "$L_ERR_INV_VER" ;; esac
    case "$BIN_NAME" in *[!a-zA-Z0-9_-]*) die "$L_ERR_INV_BIN" ;; esac

    INSTALL_DIR="$(get_realpath "$INSTALL_DIR")"
    CONFIG_DIR="$(get_realpath "$CONFIG_DIR")"
    WORK_DIR="$(get_realpath "$WORK_DIR")"
    CONFIG_FILE="$(get_realpath "$CONFIG_FILE")"

    CONFIG_PARENT_DIR="${CONFIG_FILE%/*}"
    if [ -z "$CONFIG_PARENT_DIR" ]; then CONFIG_PARENT_DIR="/"; fi
    if [ "$CONFIG_PARENT_DIR" = "$CONFIG_FILE" ]; then CONFIG_PARENT_DIR="."; fi

    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
        if [ "${USER:-}" != "root" ] && [ "${LOGNAME:-}" != "root" ]; then
            die "$L_ERR_INCORR_ROOT_LOGIN"
        fi
    else
        command -v sudo >/dev/null 2>&1 || die "$L_ERR_ROOT"
        SUDO="sudo"
        if ! sudo -n true 2>/dev/null; then
            if ! [ -t 0 ]; then
                die "$L_ERR_SUDO_TTY"
            fi
        fi
    fi

    if [ -n "$SUDO" ]; then
        if $SUDO sh -c '[ -d "$1" ]' _ "$CONFIG_FILE"; then
            die "$L_ERR_DIR_CHECK"
        fi
    elif [ -d "$CONFIG_FILE" ]; then
        die "$L_ERR_DIR_CHECK"
    fi

    for cmd in id uname awk grep find rm chown chmod mv mktemp mkdir tr dd sed ps head sleep cat tar gzip; do
        command -v "$cmd" >/dev/null 2>&1 || die "$L_ERR_CMD_NOT_FOUND $cmd"
    done
}

verify_install_deps() {
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || die "$L_ERR_NO_DL_TOOL"
    command -v cp >/dev/null 2>&1 || command -v install >/dev/null 2>&1 || die "$L_ERR_NO_CP_TOOL"

    if ! command -v setcap >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then
            $SUDO apk add --no-cache libcap-utils libcap >/dev/null 2>&1 || true
        elif command -v apt-get >/dev/null 2>&1; then
            $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q libcap2-bin >/dev/null 2>&1 || {
                $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null 2>&1 || true
                $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q libcap2-bin >/dev/null 2>&1 || true
            }
        elif command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y -q libcap >/dev/null 2>&1 || true
        elif command -v yum >/dev/null 2>&1; then $SUDO yum install -y -q libcap >/dev/null 2>&1 || true
        fi
    fi
}

check_port_availability() {
    port_info=""

    if command -v ss >/dev/null 2>&1; then
        port_info=$($SUDO ss -tulnp 2>/dev/null | grep -E ":${SERVER_PORT}([[:space:]]|$)" || true)
    elif command -v netstat >/dev/null 2>&1; then
        port_info=$($SUDO netstat -tulnp 2>/dev/null | grep -E ":${SERVER_PORT}([[:space:]]|$)" || true)
    elif command -v lsof >/dev/null 2>&1; then
        port_info=$($SUDO lsof -i :${SERVER_PORT} 2>/dev/null | grep LISTEN || true)
    else
        say "[WARNING] $L_WARN_NO_NET_TOOL"
        return 0
    fi

    if [ -n "$port_info" ]; then
        if printf '%s\n' "$port_info" | grep -q "${BIN_NAME}"; then
            say "  -> $L_INFO_PORT_IGNORE"
        else
            say "[ERROR] $L_ERR_PORT_IN_USE $SERVER_PORT:"
            printf '  %s\n' "$port_info"
            die "$L_ERR_PORT_FREE"
        fi
    fi
}

detect_arch() {
    sys_arch="$(uname -m)"
    case "$sys_arch" in
        x86_64|amd64)
            if [ -r /proc/cpuinfo ] && grep -q "avx2" /proc/cpuinfo 2>/dev/null && grep -q "bmi2" /proc/cpuinfo 2>/dev/null; then
                echo "x86_64-v3"
            else
                echo "x86_64"
            fi
            ;;
        aarch64|arm64) echo "aarch64" ;;
        *) die "$L_ERR_UNSUP_ARCH $sys_arch" ;;
    esac
}

detect_libc() {
    for f in /lib/ld-musl-*.so.* /lib64/ld-musl-*.so.*; do
        if [ -e "$f" ]; then echo "musl"; return 0; fi
    done
    if grep -qE '^ID="?alpine"?' /etc/os-release 2>/dev/null; then echo "musl"; return 0; fi
    if command -v ldd >/dev/null 2>&1 && (ldd --version 2>&1 || true) | grep -qi musl; then echo "musl"; return 0; fi
    echo "gnu"
}

fetch_file() {
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
    else wget -q -O "$2" "$1"; fi
}

# Build the binary from source as a fallback when release artifacts are
# unavailable (or BUILD_FROM_SOURCE=1). Arguments:
#   $1 = destination directory under which the built binary lives
#   $2 = git ref to check out (branch name or tag like "3.4.11")
# On success the path to the freshly built binary is written to stdout.
build_from_source() {
    _bfs_destdir="$1"
    _bfs_ref="$2"

    command -v git >/dev/null 2>&1 || die "$L_ERR_NO_GIT"
    command -v cargo >/dev/null 2>&1 || die "$L_ERR_NO_CARGO"

    _bfs_srcdir="${_bfs_destdir}/src"
    rm -rf "$_bfs_srcdir"

    # `--depth=1 --branch <ref>` works for both branch names and tag names.
    if ! git clone --depth=1 --branch "$_bfs_ref" \
            "https://github.com/${REPO}.git" "$_bfs_srcdir" >&2
    then
        # shellcheck disable=SC2059
        die "$(printf "$L_ERR_CLONE_FAIL" "$REPO" "$_bfs_ref")"
    fi

    ( cd "$_bfs_srcdir" && cargo build --release --bin "$BIN_NAME" >&2 ) \
        || die "$L_ERR_BUILD_FAIL"

    _bfs_built="${_bfs_srcdir}/target/release/${BIN_NAME}"
    if [ ! -x "$_bfs_built" ]; then
        # shellcheck disable=SC2059
        die "$(printf "$L_ERR_BUILT_BIN_MISSING" "$BIN_NAME")"
    fi

    printf '%s\n' "$_bfs_built"
}

ensure_user_group() {
    nologin_bin="$(command -v nologin 2>/dev/null || command -v false 2>/dev/null || echo /bin/false)"

    if ! check_os_entity group telemt; then
        if command -v groupadd >/dev/null 2>&1; then $SUDO groupadd -r telemt
        elif command -v addgroup >/dev/null 2>&1; then $SUDO addgroup -S telemt
        else die "$L_ERR_CREATE_GRP" ; fi
    fi

    if ! check_os_entity passwd telemt; then
        if command -v useradd >/dev/null 2>&1; then
            $SUDO useradd -r -g telemt -d "$WORK_DIR" -s "$nologin_bin" -c "Telemt Proxy" telemt
        elif command -v adduser >/dev/null 2>&1; then
            if adduser --help 2>&1 | grep -q -- '-S'; then
                $SUDO adduser -S -D -H -h "$WORK_DIR" -s "$nologin_bin" -G telemt telemt
            else
                $SUDO adduser --system --home "$WORK_DIR" --shell "$nologin_bin" --no-create-home --ingroup telemt --disabled-password telemt
            fi
        else die "$L_ERR_CREATE_USR"; fi
    fi
}

setup_dirs() {
    $SUDO mkdir -p "$WORK_DIR" "$CONFIG_DIR" "$CONFIG_PARENT_DIR" || die "$L_ERR_MKDIR"

    $SUDO chown telemt:telemt "$WORK_DIR" && $SUDO chmod 750 "$WORK_DIR"
    $SUDO chown telemt:telemt "$CONFIG_DIR" && $SUDO chmod 750 "$CONFIG_DIR"

    if [ "$CONFIG_PARENT_DIR" != "$CONFIG_DIR" ] && [ "$CONFIG_PARENT_DIR" != "." ] && [ "$CONFIG_PARENT_DIR" != "/" ]; then
        $SUDO chown root:telemt "$CONFIG_PARENT_DIR" && $SUDO chmod 750 "$CONFIG_PARENT_DIR"
    fi
}

stop_service() {
    svc="$(get_svc_mgr)"
    if [ "$svc" = "systemd" ] && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        $SUDO systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    elif [ "$svc" = "openrc" ] && rc-service "$SERVICE_NAME" status >/dev/null 2>&1; then
        $SUDO rc-service "$SERVICE_NAME" stop 2>/dev/null || true
    fi
}

install_binary() {
    bin_src="$1"; bin_dst="$2"
    if [ -e "$INSTALL_DIR" ] && [ ! -d "$INSTALL_DIR" ]; then
        die "'$INSTALL_DIR' $L_ERR_INSTALL_DIR"
    fi

    $SUDO mkdir -p "$INSTALL_DIR" || die "$L_ERR_MKDIR"

    $SUDO rm -f "$bin_dst" 2>/dev/null || true

    if command -v install >/dev/null 2>&1; then
        $SUDO install -m 0755 "$bin_src" "$bin_dst" || die "$L_ERR_BIN_INSTALL"
    else
        $SUDO cp "$bin_src" "$bin_dst" && $SUDO chmod 0755 "$bin_dst" || die "$L_ERR_BIN_COPY"
    fi

    $SUDO sh -c '[ -x "$1" ]' _ "$bin_dst" || die "$L_ERR_BIN_EXEC $bin_dst"

    if command -v setcap >/dev/null 2>&1; then
        $SUDO setcap cap_net_bind_service,cap_net_admin=+ep "$bin_dst" 2>/dev/null || true
    fi
}

generate_secret() {
    secret="$(command -v openssl >/dev/null 2>&1 && openssl rand -hex 16 2>/dev/null || true)"
    if [ -z "$secret" ] || [ "${#secret}" -ne 32 ]; then
        if command -v od >/dev/null 2>&1; then secret="$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
        elif command -v hexdump >/dev/null 2>&1; then secret="$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | hexdump -e '1/1 "%02x"')"
        elif command -v xxd >/dev/null 2>&1; then secret="$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | xxd -p | tr -d '\n')"
        fi
    fi
    if [ "${#secret}" -eq 32 ]; then echo "$secret"; else return 1; fi
}

generate_config_content() {
    conf_secret="$1"
    conf_tag="$2"
    escaped_tls_domain="$(printf '%s\n' "$TLS_DOMAIN" | tr -d '[:cntrl:]' | sed 's/\\/\\\\/g; s/"/\\"/g')"

    cat <<EOF
[general]
use_middle_proxy = true
EOF

    if [ -n "$conf_tag" ]; then
        echo "ad_tag = \"${conf_tag}\""
    fi

    cat <<EOF

[general.modes]
classic = false
secure = false
tls = true

[server]
port = ${SERVER_PORT}

[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.1/32"]

[censorship]
tls_domain = "${escaped_tls_domain}"

[access.users]
hello = "${conf_secret}"
EOF
}

install_config() {
    if is_config_exists; then
        say "  -> $L_INFO_CONF_EXISTS"

        tmp_conf="${TEMP_DIR}/config.tmp"
        $SUDO cat "$CONFIG_FILE" > "$tmp_conf"

        escaped_domain="$(printf '%s\n' "$TLS_DOMAIN" | tr -d '[:cntrl:]' | sed 's/\\/\\\\/g; s/"/\\"/g')"

        awk -v port="$SERVER_PORT" -v secret="$USER_SECRET" -v domain="$escaped_domain" -v ad_tag="$AD_TAG" \
            -v flag_p="$PORT_PROVIDED" -v flag_s="$SECRET_PROVIDED" -v flag_d="$DOMAIN_PROVIDED" -v flag_a="$AD_TAG_PROVIDED" '
        BEGIN { ad_tag_handled = 0 }

        flag_p == "1" && /^[ \t]*port[ \t]*=/ { print "port = " port; next }
        flag_s == "1" && /^[ \t]*hello[ \t]*=/ { print "hello = \"" secret "\""; next }
        flag_d == "1" && /^[ \t]*tls_domain[ \t]*=/ { print "tls_domain = \"" domain "\""; next }

        flag_a == "1" && /^[ \t]*ad_tag[ \t]*=/ {
            if (!ad_tag_handled) {
                print "ad_tag = \"" ad_tag "\"";
                ad_tag_handled = 1;
            }
            next
        }
        flag_a == "1" && /^\[general\]/ {
            print;
            if (!ad_tag_handled) {
                print "ad_tag = \"" ad_tag "\"";
                ad_tag_handled = 1;
            }
            next
        }

        { print }
        ' "$tmp_conf" > "${tmp_conf}.new" && mv "${tmp_conf}.new" "$tmp_conf"

        [ "$PORT_PROVIDED" -eq 1 ] && say "  -> $L_INFO_UPD_PORT $SERVER_PORT"
        [ "$SECRET_PROVIDED" -eq 1 ] && say "  -> $L_INFO_UPD_SEC"
        [ "$DOMAIN_PROVIDED" -eq 1 ] && say "  -> $L_INFO_UPD_DOM $TLS_DOMAIN"
        [ "$AD_TAG_PROVIDED" -eq 1 ] && say "  -> $L_INFO_UPD_TAG"

        write_root "$CONFIG_FILE" < "$tmp_conf"
        rm -f "$tmp_conf"
        return 0
    fi

    if [ -z "$USER_SECRET" ]; then
        USER_SECRET="$(generate_secret)" || die "$L_ERR_GEN_SEC"
    fi

    generate_config_content "$USER_SECRET" "$AD_TAG" | write_root "$CONFIG_FILE" || die "$L_ERR_CONF_INST"
    $SUDO chown root:telemt "$CONFIG_FILE" && $SUDO chmod 640 "$CONFIG_FILE"

    say "  -> $L_INFO_CONF_OK"
    say "  -> $L_INFO_CONF_SEC $USER_SECRET"
}

generate_systemd_content() {
    cat <<EOF
[Unit]
Description=Telemt
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=telemt
Group=telemt
WorkingDirectory=$WORK_DIR
ExecStart="${INSTALL_DIR}/${BIN_NAME}" "${CONFIG_FILE}"
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
}

generate_openrc_content() {
    cat <<EOF
#!/sbin/openrc-run
name="$SERVICE_NAME"
description="Telemt Proxy Service"
command="${INSTALL_DIR}/${BIN_NAME}"
command_args="${CONFIG_FILE}"
command_background=true
command_user="telemt:telemt"
pidfile="/run/\${RC_SVCNAME}.pid"
directory="${WORK_DIR}"
rc_ulimit="-n 65536"
depend() { need net; use logger; }
EOF
}

install_service() {
    svc="$(get_svc_mgr)"
    if [ "$svc" = "systemd" ]; then
        generate_systemd_content | write_root "/etc/systemd/system/${SERVICE_NAME}.service"
        $SUDO chown root:root "/etc/systemd/system/${SERVICE_NAME}.service" && $SUDO chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"

        $SUDO systemctl daemon-reload || true
        $SUDO systemctl enable "$SERVICE_NAME" || true

        if ! $SUDO systemctl start "$SERVICE_NAME"; then
            say "[WARNING] $L_WARN_SVC_FAIL"
            SERVICE_START_FAILED=1
        fi
    elif [ "$svc" = "openrc" ]; then
        generate_openrc_content | write_root "/etc/init.d/${SERVICE_NAME}"
        $SUDO chown root:root "/etc/init.d/${SERVICE_NAME}" && $SUDO chmod 0755 "/etc/init.d/${SERVICE_NAME}"

        $SUDO rc-update add "$SERVICE_NAME" default 2>/dev/null || true

        if ! $SUDO rc-service "$SERVICE_NAME" start 2>/dev/null; then
            say "[WARNING] $L_WARN_SVC_FAIL"
            SERVICE_START_FAILED=1
        fi
    else
        cmd="\"${INSTALL_DIR}/${BIN_NAME}\" \"${CONFIG_FILE}\""
        if [ -n "$SUDO" ]; then
            say "  -> $L_INFO_MANUAL_START sudo -u telemt $cmd"
        else
            say "  -> $L_INFO_MANUAL_START su -s /bin/sh telemt -c '$cmd'"
        fi
    fi
}

kill_user_procs() {
    if command -v pkill >/dev/null 2>&1; then
        $SUDO pkill -u telemt "$BIN_NAME" 2>/dev/null || true
        sleep 1
        $SUDO pkill -9 -u telemt "$BIN_NAME" 2>/dev/null || true
    else
        if command -v pgrep >/dev/null 2>&1; then
            pids="$(pgrep -u telemt 2>/dev/null || true)"
        else
            pids="$(ps -ef 2>/dev/null | awk '$1=="telemt"{print $2}' || true)"
            [ -z "$pids" ] && pids="$(ps 2>/dev/null | awk '$2=="telemt"{print $1}' || true)"
        fi

        if [ -n "$pids" ]; then
            for pid in $pids; do
                case "$pid" in ''|*[!0-9]*) continue ;; *) $SUDO kill "$pid" 2>/dev/null || true ;; esac
            done
            sleep 1
            for pid in $pids; do
                case "$pid" in ''|*[!0-9]*) continue ;; *) $SUDO kill -9 "$pid" 2>/dev/null || true ;; esac
            done
        fi
    fi
}

uninstall() {
    say "$L_INFO_UNINST_START $BIN_NAME..."

    say "$L_U_STAGE_1"
    stop_service

    say "$L_U_STAGE_2"
    svc="$(get_svc_mgr)"
    if [ "$svc" = "systemd" ]; then
        $SUDO systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        $SUDO rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        $SUDO systemctl daemon-reload 2>/dev/null || true
    elif [ "$svc" = "openrc" ]; then
        $SUDO rc-update del "$SERVICE_NAME" 2>/dev/null || true
        $SUDO rm -f "/etc/init.d/${SERVICE_NAME}"
    fi

    say "$L_U_STAGE_3"
    kill_user_procs

    say "$L_U_STAGE_4"
    $SUDO rm -f "${INSTALL_DIR}/${BIN_NAME}"

    if [ "$ACTION" = "purge" ]; then
        say "$L_U_STAGE_5"
        $SUDO rm -rf "$CONFIG_DIR" "$WORK_DIR"
        $SUDO rm -f "$CONFIG_FILE"

        if check_os_entity passwd telemt; then
            $SUDO userdel telemt 2>/dev/null || $SUDO deluser telemt 2>/dev/null || true
        fi

        if check_os_entity group telemt; then
            $SUDO groupdel telemt 2>/dev/null || $SUDO delgroup telemt 2>/dev/null || true
        fi
    else
        say "$L_INFO_KEEP_CONF"
    fi

    printf '\n====================================================================\n'
    printf '                    %s\n' "$L_OUT_UNINST_H"
    printf '====================================================================\n\n'
    exit 0
}

case "$ACTION" in
    help) show_help ;;
    uninstall|purge) verify_common; uninstall ;;
    install)
        say "$L_INFO_I_START $BIN_NAME (Version: $TARGET_VERSION)"

        say "$L_I_STAGE_1"
        verify_common
        verify_install_deps

        if is_config_exists; then
            ext_port="$($SUDO awk -F'=' '/^[ \t]*port[ \t]*=/ {gsub(/[^0-9]/, "", $2); print $2; exit}' "$CONFIG_FILE" 2>/dev/null || true)"
            if [ -n "$ext_port" ] && [ "$PORT_PROVIDED" -eq 0 ]; then
                SERVER_PORT="$ext_port"
            fi

            ext_secret="$($SUDO awk -F'"' '/^[ \t]*hello[ \t]*=/ {print $2; exit}' "$CONFIG_FILE" 2>/dev/null || true)"
            if [ -n "$ext_secret" ] && [ "$SECRET_PROVIDED" -eq 0 ]; then
                USER_SECRET="$ext_secret"
            fi

            ext_domain="$($SUDO awk -F'"' '/^[ \t]*tls_domain[ \t]*=/ {print $2; exit}' "$CONFIG_FILE" 2>/dev/null || true)"
            if [ -n "$ext_domain" ] && [ "$DOMAIN_PROVIDED" -eq 0 ]; then
                TLS_DOMAIN="$ext_domain"
            fi
        fi

        check_port_availability

        if [ "$DOMAIN_PROVIDED" -eq 0 ]; then
            say "$L_I_STAGE_1_5"
            if [ -t 0 ] || [ -c /dev/tty ]; then
                printf "$L_I_PROMPT_DOM" "$TLS_DOMAIN"
                read -r input_domain </dev/tty || input_domain=""
                if [ -n "$input_domain" ]; then
                    TLS_DOMAIN="$input_domain"
                fi
            else
                say "[WARNING] $L_WARN_NO_TTY $TLS_DOMAIN"
            fi
            DOMAIN_PROVIDED=1
        fi

        if [ "$TARGET_VERSION" != "latest" ]; then
            TARGET_VERSION="${TARGET_VERSION#v}"
        fi

        ARCH="$(detect_arch)"; LIBC="$(detect_libc)"
        FILE_NAME="${BIN_NAME}-${ARCH}-linux-${LIBC}.tar.gz"

        if [ "$TARGET_VERSION" = "latest" ]; then
            DL_URL="https://github.com/${REPO}/releases/latest/download/${FILE_NAME}"
        else
            DL_URL="https://github.com/${REPO}/releases/download/${TARGET_VERSION}/${FILE_NAME}"
        fi

        say "$L_I_STAGE_2"
        TEMP_DIR="$(mktemp -d)" || die "$L_ERR_TMP_DIR"
        if [ -z "$TEMP_DIR" ] || [ ! -d "$TEMP_DIR" ]; then
            die "$L_ERR_TMP_INV"
        fi

        # Decide whether to download a release artifact or build from source.
        # BUILD_FROM_SOURCE=1 → skip download entirely. Otherwise try the
        # release tarball (with the historical x86_64-v3 → x86_64 fallback)
        # and, only if every download fails, fall back to git clone + cargo
        # build --release of the requested ref.
        EXTRACTED_BIN=""
        BUILD_REF="$BRANCH"
        if [ "$TARGET_VERSION" != "latest" ]; then
            BUILD_REF="$TARGET_VERSION"
        fi
        DOWNLOAD_OK=0

        if [ "$BUILD_FROM_SOURCE" != "1" ]; then
            if fetch_file "$DL_URL" "${TEMP_DIR}/${FILE_NAME}"; then
                DOWNLOAD_OK=1
            elif [ "$ARCH" = "x86_64-v3" ]; then
                say "  -> $L_INFO_FALLBACK"
                ARCH="x86_64"
                FILE_NAME="${BIN_NAME}-${ARCH}-linux-${LIBC}.tar.gz"
                if [ "$TARGET_VERSION" = "latest" ]; then
                    DL_URL="https://github.com/${REPO}/releases/latest/download/${FILE_NAME}"
                else
                    DL_URL="https://github.com/${REPO}/releases/download/${TARGET_VERSION}/${FILE_NAME}"
                fi
                if fetch_file "$DL_URL" "${TEMP_DIR}/${FILE_NAME}"; then
                    DOWNLOAD_OK=1
                fi
            fi
        fi

        if [ "$DOWNLOAD_OK" -eq 1 ]; then
            say "$L_I_STAGE_3"
            if ! gzip -dc "${TEMP_DIR}/${FILE_NAME}" | tar -xf - -C "$TEMP_DIR" 2>/dev/null; then
                die "$L_ERR_EXTRACT"
            fi
            EXTRACTED_BIN="$(find "$TEMP_DIR" -type f -name "$BIN_NAME" -print 2>/dev/null | head -n 1 || true)"
        else
            if [ "$BUILD_FROM_SOURCE" != "1" ]; then
                # shellcheck disable=SC2059
                say "  -> $(printf "$L_INFO_BUILD_FALLBACK" "$BUILD_REF")"
            fi
            say "$L_I_BUILD_START"
            EXTRACTED_BIN="$(build_from_source "$TEMP_DIR" "$BUILD_REF")"
        fi
        [ -n "$EXTRACTED_BIN" ] || die "$L_ERR_BIN_NOT_FOUND"

        say "$L_I_STAGE_4"
        ensure_user_group; setup_dirs; stop_service

        say "$L_I_STAGE_5"
        install_binary "$EXTRACTED_BIN" "${INSTALL_DIR}/${BIN_NAME}"

        say "$L_I_STAGE_6"
        install_config

        say "$L_I_STAGE_7"
        install_service

        if [ "${SERVICE_START_FAILED:-0}" -eq 1 ]; then
            printf '\n====================================================================\n'
            printf '               %s\n' "$L_OUT_WARN_H"
            printf '====================================================================\n\n'
            printf '%b' "$L_OUT_WARN_D"
        else
            printf '\n====================================================================\n'
            printf '                      %s\n' "$L_OUT_SUCC_H"
            printf '====================================================================\n\n'
        fi

        SERVER_IP=""
        if command -v curl >/dev/null 2>&1; then SERVER_IP="$(curl -s4 -m 3 ifconfig.me 2>/dev/null || curl -s4 -m 3 api.ipify.org 2>/dev/null || true)"
        elif command -v wget >/dev/null 2>&1; then SERVER_IP="$(wget -qO- -T 3 ifconfig.me 2>/dev/null || wget -qO- -T 3 api.ipify.org 2>/dev/null || true)"; fi
        [ -z "$SERVER_IP" ] && SERVER_IP="<YOUR_SERVER_IP>"

        if command -v xxd >/dev/null 2>&1; then HEX_DOMAIN="$(printf '%s' "$TLS_DOMAIN" | xxd -p | tr -d '\n')"
        elif command -v hexdump >/dev/null 2>&1; then HEX_DOMAIN="$(printf '%s' "$TLS_DOMAIN" | hexdump -v -e '/1 "%02x"')"
        elif command -v od >/dev/null 2>&1; then HEX_DOMAIN="$(printf '%s' "$TLS_DOMAIN" | od -A n -t x1 | tr -d ' \n')"
        else HEX_DOMAIN=""; fi

        CLIENT_SECRET="ee${USER_SECRET}${HEX_DOMAIN}"

        printf '%b\n' "$L_OUT_LINK"
        printf '  tg://proxy?server=%s&port=%s&secret=%s\n\n' "$SERVER_IP" "$SERVER_PORT" "$CLIENT_SECRET"

        svc="$(get_svc_mgr)"
        if [ "$svc" = "systemd" ]; then
            printf '%s\n' "$L_OUT_LOGS"
            printf '  sudo journalctl -u %s -f\n\n' "$SERVICE_NAME"
        elif [ "$svc" = "openrc" ]; then
            printf '%s\n' "$L_OUT_LOGS"
            printf '  sudo tail -f /var/log/messages /var/log/syslog 2>/dev/null | grep -i %s\n\n' "$SERVICE_NAME"
        fi

        printf '====================================================================\n'
        ;;
esac
