- [Введение](#введение)
- [Прозрачный выборочный заворот TCP соединений на роутере через SOCKS](#прозрачный-выборочный-заворот-tcp-соединений-на-роутере-через-socks)
  - [Сделать так, чтобы все время при загрузке системы на некотором порту возникал SOCKS](#сделать-так-чтобы-все-время-при-загрузке-системы-на-некотором-порту-возникал-socks)
  - [Организовать прозрачную соксификацию](#организовать-прозрачную-соксификацию)
  - [Завертывание соединений через `iptables`](#завертывание-соединений-через-iptables)
  - [Завертывание соединений через `nftables`](#завертывание-соединений-через-nftables)
  - [Проверка](#проверка)

# Введение

Данный мануал пишется не как копипастная инструкция, а как помощь уже соображающему.
Если вы не знаете основ сетей, Linux, OpenWrt, а пытаетесь что-то скопипастить отсюда без малейшего понимания смысла, то маловероятно, что у вас что-то заработает. Не тратьте свое время напрасно.
Цель - донести принципы как это настраивается вообще, а не указать какую буковку где вписать.

# Прозрачный выборочный заворот TCP соединений на роутере через SOCKS

Tor поддерживает "из коробки" режим transparent proxy. Это можно использовать в теории, но практически - только на роутерах с 128 мб памяти и выше. И тор еще и тормозной.
Другой вариант напрашивается, если у вас есть доступ к какой-нибудь unix системе с SSH, где сайты не блокируются.
Например, у вас есть VPS вне России. Понятийно требуются следующие шаги:

1) Выделять IP, на которые надо проксировать трафик. У нас уже имеется ipset `zapret`, технология создания которого отработана.
2) Сделать так, чтобы все время при загрузке системы на некотором порту возникал SOCKS.
3) Установить transparent соксификатор. Redsocks прекрасно подошел на эту роль.
4) Завернуть через `iptables` или `nftables` трафик с порта назначения 443 и на IP адреса из `ipset`/`nfset` `zapret` на соксификатор.

Тоже самое сделать с `ipset`/`nfset` `ipban` для всех TCP портов.
Буду рассматривать систему на базе OpenWrt, где уже установлена система обхода DPI `zapret`.
Если вам не нужны функции обхода DPI, можно выбрать режим `MODE=filter`.

## Сделать так, чтобы все время при загрузке системы на некотором порту возникал SOCKS

Т.к. дефолтный `dropbear` клиент не поддерживает создание SOCKS, то для начала придется заменить `dropbear` SSH client на `OpenSSH`: пакеты `openssh-client` и `openssh-client-utils`.
Устанавливать их нужно с опцией `opkg --force-overwrite`, поскольку они перепишут SSH клиент от `dropbear`.
После установки пакетов расслабим неоправданно жестокие права: `chmod 755 /etc/ssh`.
Следует создать пользователя, под которым будем крутить SSH client. Допустим, это будет 'proxy'.
Сначала установить пакет `shadow-useradd`, потом:

```sh
useradd -d /home/proxy proxy
mkdir -p /home/proxy
chown proxy:proxy /home/proxy
```

OpenSSH ловит разные глюки, если у него нет доступа к `/dev/tty`.
Добавим в `/etc/rc.local` строчку: `chmod 666 /dev/tty`.
Сгенерируем для него ключ RSA для доступа к SSH серверу:

```sh
su proxy
cd
mkdir -m 700 .ssh
cd .ssh
ssh-keygen
ls
exit
```

Должны получиться файлы `id_rsa` и `id_rsa.pub`.
Строчку из `id_rsa.pub` следует добавить на SSH сервер в файл `$HOME/.ssh/authorized_keys`.
Более подробно о доступе к SSH через авторизацию по ключам [здесь](https://beget.com/ru/articles/ssh_by_key).
Предположим, ваш SSH сервер - vps.mydomain.com, пользователь называется `proxy`.
Проверить подключение можно так: `ssh -N -D 1098 -l proxy vps.mydomain.com`.
Сделайте это под пользователем `proxy`, поскольку при первом подключении SSH спросит о правильности hostkey.
Соединение может отвалиться в любой момент, поэтому нужно зациклить запуск SSH.
Для этого лучший вариант - использовать `procd` - упрощенная замена `systemd` на OpenWrt версий BB и выше.

`/etc/init.d/socks_vps`:

```sh
# !/bin/sh /etc/rc.common
START=50
STOP=50
USE_PROCD=1
USERNAME=proxy
COMMAND="ssh -N -D 1098 -l proxy vps.mydomain.com"
start_service() {
    procd_open_instance
    procd_set_param user $USERNAME
    procd_set_param respawn 10 10 0
    procd_set_param command $COMMAND
    procd_close_instance
}
```

Этому файлу нужно дать права: `chmod +x /etc/init.d/socks_vps`.
Запуск: `/etc/init.d/socks_vps start`.
Останов: `/etc/init.d/socks_vps stop`.
Включить автозагрузку: `/etc/init.d/socks_vps enable`.
Проверка: `curl -4 --socks5 127.0.0.1:1098 https://rutracker.org`.

## Организовать прозрачную соксификацию

Установить пакет `redsocks`, прописать конфиг:

`/etc/redsocks.conf`:

```
base {
        log_debug = off;
        log_info = on;
        log = "syslog:local7";
        daemon = on;
        user = nobody;
        group = nogroup;
        redirector = iptables;
}
redsocks {
        local_ip = 127.0.0.127;
        local_port = 1099;
        ip = 127.0.0.1;
        port = 1098;
        type = socks5;
}
```

После чего перезапускаем: `/etc/init.d/redsocks restart`.
Смотрим появился ли листенер: `netstat -tnlp | grep 1099`.

В `zapret` для перенаправления DNAT на интерфейс lo используется 127.0.0.127.
Ко всем остальным адресам из 127.0.0.0/8 DNAT может быть заблокирован. Читайте `readme.md` про `route_localnet`.

## Завертывание соединений через `iptables`

**ВНИМАНИЕ:** Версии OpenWrt до 21.02 включительно используют `iptables` + `fw3`.
Более новые перешили на `nftables` по умолчанию.
В новых OpenWrt можно снести `firewall4` и `nftables`, заменив их на `firewall3` + `iptables`.
Инструкция относится только к OpenWrt, где используется `iptables`.

Будем завертывать любые TCP соединения на IP из ipset `ipban` и HTTPS на IP из ipset `zapret`, за исключением IP из ipset `nozapret`.

`/etc/firewall.user`:

```sh
SOXIFIER_PORT=1099

. /opt/zapret/init.d/openwrt/functions

create_ipset no-update

network_find_wan4_all wan_iface
for ext_iface in $wan_iface; do
    network_get_device ext_device $ext_iface
    ipt OUTPUT -t nat -o $ext_device -p tcp --dport 443 -m set --match-set zapret dst -m set ! --match-set nozapret dst -j REDIRECT --to-port $SOXIFIER_PORT
    ipt OUTPUT -t nat -o $ext_device -p tcp -m set --match-set ipban dst -m set ! --match-set nozapret dst -j REDIRECT --to-port $SOXIFIER_PORT
done

prepare_route_localnet

ipt prerouting_lan_rule -t nat -p tcp --dport 443 -m set --match-set zapret dst -m set ! --match-set nozapret -j DNAT --to $TPWS_LOCALHOST4:$SOXIFIER_PORT
ipt prerouting_lan_rule -t nat -p tcp -m set --match-set ipban dst -m set ! --match-set nozapret -j DNAT --to $TPWS_LOCALHOST4:$SOXIFIER_PORT
```

Внести параметр "reload" в указанное место. `/etc/config/firewall`:

```
config include
        option path '/etc/firewall.user'
        option reload '1'
```

Перезапуск firewall: `/etc/init.d/firewall restart`

## Завертывание соединений через `nftables`

**ВНИМАНИЕ:** Только для версий OpenWrt старше 21.02.

`nftables` не могут использовать ipset. Вместо `ipset` существует аналог - `nfset`.
`nfset` является частью таблицы nftable и принадлежит только к ней. Адресация `nfset` из другой nftable невозможна.
Скрипты `ipset/*` в случае `nftables` используют `nfset`-ы в таблице `zapret`.
Чтобы использовать эти `nfset`-ы в своих правилах, необходимо синхронизироваться с их созданием и вносить свои цепочки в nftable `zapret`.
Для этого существуют хуки - скрипты, вызываемые из `zapret` на определенных стадиях инициализации фаервола.

Раскомментируйте в `/opt/zapret/config` строчку:

```sh
INIT_FW_POST_UP_HOOK="/etc/firewall.zapret.hook.post_up"
```

Создайте файл `/etc/firewall.zapret.hook.post_up` и присвойте ему `chmod 755`:

```sh
#!/bin/sh

SOXIFIER_PORT=1099

. /opt/zapret/init.d/openwrt/functions

cat << EOF | nft -f - 2>/dev/null
 delete chain inet $ZAPRET_NFT_TABLE my_output
 delete chain inet $ZAPRET_NFT_TABLE my_prerouting
EOF

prepare_route_localnet

cat << EOF | nft -f -
 add chain inet $ZAPRET_NFT_TABLE my_output { type nat hook output priority -102; }
 flush chain inet $ZAPRET_NFT_TABLE my_output
 add rule inet $ZAPRET_NFT_TABLE my_output oifname @wanif meta l4proto tcp ip daddr @ipban ip daddr != @nozapret dnat to $TPWS_LOCALHOST4:$SOXIFIER_PORT
 add rule inet $ZAPRET_NFT_TABLE my_output oifname @wanif tcp dport 443 ip daddr @zapret ip daddr != @nozapret dnat to $TPWS_LOCALHOST4:$SOXIFIER_PORT

add chain inet $ZAPRET_NFT_TABLE my_prerouting { type nat hook prerouting priority -102; }
 flush chain inet $ZAPRET_NFT_TABLE my_prerouting
 add rule inet $ZAPRET_NFT_TABLE my_prerouting iifname @lanif meta l4proto tcp ip daddr @ipban ip daddr != @nozapret dnat to $TPWS_LOCALHOST4:$SOXIFIER_PORT
 add rule inet $ZAPRET_NFT_TABLE my_prerouting iifname @lanif tcp dport 443 ip daddr @zapret ip daddr != @nozapret dnat to $TPWS_LOCALHOST4:$SOXIFIER_PORT
EOF
```

Перезапуск firewall: `/etc/init.d/zapret restart_fw`

## Проверка

Все, теперь можно проверять:

```sh
/etc/init.d/redsocks stop
curl -4 https://rutracker.org
```

Должно обломаться с надписью "Connection refused".
Если не обламывается - значит IP адрес rutracker.org не в ipset, либо не сработали правила фаервола.
Например, из-за не установленных модулей `iptables`.

```sh
/etc/init.d/redsocks start
curl -4 https://rutracker.org
```

Должно выдать страницу.
