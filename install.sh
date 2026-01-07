#!/bin/sh
# Установщик zapret с автоматическим скачиванием latest релиза
# Работает на OpenWrt и других Linux с sh, wget/curl, tar

set -e  # Выходим при любой ошибке

REPO="commensal/zapret-commensal"
TARGET_DIR="/data/zapret"
TMP_DIR="/tmp/zapret_install_$$"

echo "Создаём временные и целевые директории..."
mkdir -p "$TMP_DIR" "$TARGET_DIR"
cd "$TMP_DIR"

echo "Получаем URL последней версии tar.gz архива с GitHub..."
# Получаем URL на обычный tar.gz (не embedded, чтобы были все скрипты)
ARCHIVE_URL=$(curl -s https://api.github.com/repos/$REPO/releases/latest | \
    grep "browser_download_url.*tar.gz" | \
    grep -v "embedded" | \
    cut -d '"' -f 4)

if [ -z "$ARCHIVE_URL" ]; then
    echo "Ошибка: не найден tar.gz архив в последнем релизе!"
    echo "Проверьте https://github.com/$REPO/releases"
    exit 1
fi

echo "Скачиваем latest релиз: $ARCHIVE_URL"
wget "$ARCHIVE_URL" -O zapret_latest.tar.gz || curl -fsSL "$ARCHIVE_URL" -o zapret_latest.tar.gz

echo "Распаковываем с перезаписью в $TARGET_DIR..."
tar -xzf zapret_latest.tar.gz -C "$TARGET_DIR" --strip-components=1 --overwrite

echo "Устанавливаем права 755 на все файлы и папки рекурсивно..."
chmod -R 755 "$TARGET_DIR"

cd "$TARGET_DIR"

echo "Запускаем install_easy.sh..."
if [ -f "./install_easy.sh" ]; then
    ./install_easy.sh
else
    echo "Предупреждение: install_easy.sh не найден!"
fi

echo "Запускаем install_patch.sh..."
if [ -f "./install_patch.sh" ]; then
    ./install_patch.sh
else
    echo "Предупреждение: install_patch.sh не найден!"
fi

echo ""
echo "zapret установлен. Конфигурация находится в файле /data/zapret/config"
echo "после редактирования конфига и/или листов не забывайте делать перезапуск командой"
echo "service zapret restart"

# Очистка временных файлов
cd /
rm -rf "$TMP_DIR"

echo "Готово!"