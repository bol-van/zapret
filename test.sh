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

# Очистка списка
sites_clean=$(echo "$SITES" | grep -v '^#' | grep -v '^\s*$')
total=$(echo "$sites_clean" | wc -l)
half=$(( (total + 1) / 2 ))

# Формируем список БЕЗ ведущего пробела
sites_list=""
for site in $sites_clean; do
    [ -z "$sites_list" ] && sites_list="$site" || sites_list="$sites_list $site"
done

# Цикл вывода
idx=1
while [ $idx -le $half ]; do
    left=$(echo "$sites_list" | cut -d' ' -f$idx)
    right_idx=$((idx + half))
    right=$(echo "$sites_list" | cut -d' ' -f$right_idx)

    # Выравнивание
    left_pad=$(printf "%-25s" "$left")
    right_pad=$( [ -n "$right" ] && printf "%-25s" "$right" || echo "" )

    # Проверка доступности
    if curl -Is --connect-timeout 3 --max-time 4 "https://$left" >/dev/null 2>&1; then
        left_color="[${GREEN}OK${NC}] "
    else
        left_color="[${RED}FAIL${NC}] "
    fi

    if [ -n "$right" ]; then
        if curl -Is --connect-timeout 3 --max-time 4 "https://$right" >/dev/null 2>&1; then
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