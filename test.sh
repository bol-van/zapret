#!/bin/sh

GREEN="\033[1;32m"
RED="\033[1;31m"
NC="\033[0m"

echo -e "${GREEN}===== Доступность сайтов =====${NC}"

SITES=$(cat <<'EOF'
gosuslugi.ru
esia.gosuslugi.ru
nalog.ru
lkfl2.nalog.ru
rutube.ru
youtube.com
instagram.com
rutor.info
ntc.party
rutracker.org
epidemz.net.co
nnmclub.to
openwrt.org
sxyprn.net
pornhub.com
discord.com
x.com
filmix.my
flightradar24.com
cdn77.com
play.google.com
genderize.io
EOF
)

# Очистка списка от пустых строк и комментариев
sites_clean=$(echo "$SITES" | grep -v '^#' | grep -v '^\s*$')

# Подсчёт количества
total=$(echo "$sites_clean" | wc -l)
half=$(( (total + 1) / 2 ))

# Формируем список без ведущего пробела
sites_list=""
for site in $sites_clean; do
    [ -z "$sites_list" ] && sites_list="$site" || sites_list="$sites_list $site"
done

# Цикл вывода в две колонки
idx=1
while [ $idx -le $half ]; do
    left=$(echo "$sites_list" | cut -d' ' -f$idx)
    right_idx=$((idx + half))
    right=$(echo "$sites_list" | cut -d' ' -f$right_idx)

    # Выравнивание по 25 символам
    left_pad=$(printf "%-25s" "$left")
    right_pad=$( [ -n "$right" ] && printf "%-25s" "$right" || echo "" )

    # Реалистичная проверка: User-Agent браузера, следование редиректам, увеличенные таймауты
    if curl -ILs --connect-timeout 5 --max-time 12 \
        -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36" \
        "https://$left" >/dev/null 2>&1; then
        left_color="[${GREEN}OK${NC}] "
    else
        left_color="[${RED}FAIL${NC}] "
    fi

    if [ -n "$right" ]; then
        if curl -ILs --connect-timeout 5 --max-time 12 \
            -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36" \
            "https://$right" >/dev/null 2>&1; then
            right_color="[${GREEN}OK${NC}] "
        else
            right_color="[${RED}FAIL${NC}] "
        fi
        echo -e "$left_color$left_pad $right_color$right_pad"
    else
        echo -e "$left_color$left_pad"
    fi

    idx=$((idx + 1))
done