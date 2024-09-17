- [Предисловие](#предисловие)
- [План действий](#план-действий)
  - [Если нет своего сервера](#если-нет-своего-сервера)
  - [Поднятие сервера](#поднятие-сервера)
- [Подготовка `zapret`](#подготовка-zapret)
  - [Маркировка трафика `iptables`](#маркировка-трафика-iptables)
  - [Маркировка трафика `nftables`](#маркировка-трафика-nftables)
  - [По поводу двойного NAT](#по-поводу-двойного-nat)
- [Как мне отправлять на VPN весь трафик с bittorrent?](#как-мне-отправлять-на-vpn-весь-трафик-с-bittorrent)
  - [Автоматизация проброса портов через `miniupnd`](#автоматизация-проброса-портов-через-miniupnd)

# Предисловие

Данный мануал пишется не как копипастная инструкция, а как помощь уже соображающему.
Если вы не знаете основ сетей, Linux, OpenWrt, а пытаетесь что-то скопипастить отсюда без малейшего понимания смысла, то маловероятно, что у вас что-то заработает. Не тратьте свое время напрасно.
Цель - донести принципы как это настраивается вообще, а не указать какую буковку где вписать.

# План действий

Есть возможность поднять свой VPN сервер? Не хотим использовать redsocks?
Хотим завертывать на VPN только часть трафика?
Например, из ipset zapret только порт TCP:443, из ipban - весь трафик, не только TCP?
Да, с VPN такое возможно.

Опишу понятийно, как настраивается policy based routing в OpenWrt на примере WireGuard.
Вместо WireGuard можно использовать OpenVPN или любой другой. Но WireGuard прекрасен сразу несколькими вещами, главная из которых - в разы большая скорость, даже немного превышающая IPsec.
Ведь OpenVPN основан на tun, а tun - всегда в разы медленнее решения в kernel mode, и если для PC оно может быть не так актуально, для soho роутеров - более чем.
WireGuard может дать 50 mbps там, где OpenVPN еле тащит 10.
Но есть и дополнительное требование. WireGuard работает в ядре, значит ядро должно быть под вашим контролем. VPS на базе OpenVZ не подойдет. Нужен Xen, KVM, любой другой вариант, где загружается ваше собственное ядро, а не используется общее, разделяемое на множество VPS.

Понятийно необходимо выполнить следующие шаги :

1) Поднять VPN сервер.
2) Настроить VPN клиент.

Результат этого шага - получение поднятого интерфейса VPN.
Будь то WireGuard, OpenVPN или любой другой тип VPN.

3) Создать такую схему маршрутизации, при которой пакеты, помечаемые особым mark, попадают на VPN, а остальные идут обычным способом.
4) Создать правила, выставляющие mark для всего трафика, который необходимо рулить на VPN.

Критерии могут быть любые, ограниченные лишь возможностями `iptables` и вашим воображением.

Будем считать, что наш VPN сервер находится на IP 91.15.68.202.
Вешать его будем на UDP порт 12345. На этот же порт будем вешать и клиентов.
Сервер работает под Debian 9 или выше. Клиент работает под OpenWrt.
Для VPN отведем подсеть 192.168.254.0/24.

## Если нет своего сервера

Но есть конфиг от VPN провайдера или от друга "Васи", который захотел с вами поделиться.
Тогда вам не надо настраивать сервер, задача упрощается. Делается невозможным вариант настройки без masquerade (см. ниже).
Из конфига вытаскиваете приватный ключ своего пира и публичный ключ сервера, IP/host/port сервера, используете их в настройках OpenWrt вместо сгенеренных самостоятельно.

## Поднятие сервера

WireGuard был включен в ядро Linux с версии 5.6.
Если у вас ядро >=5.6, то достаточно установить пакет `wireguard-tools`. Он содержит user-mode компоненты WireGuard.
Посмотрите, возможно, в вашем дистрибутиве ядро по умолчанию более старое, но в репозитории имеются бэкпорты новых версий. Лучше будет обновить ядро из репозитория.

В репозитории может быть пакет `wireguard-dkms`. Это автоматизированное средство сборки WireGuard с исходников, в том числе модуль ядра. Можно пользоваться им.
Иначе вам придется собрать WireGuard самому. Ядро должно быть не ниже 3.10.
На сервере должны быть установлены заголовки ядра (`linux-headers-...`) и компилятор `gcc`.

```sh
git clone --depth 1 https://git.zx2c4.com/wireguard-linux-compat
cd wireguard-linux-compat/src
make
strip --strip-debug wireguard.ko
sudo make install
```

WireGuard основан на понятии криптороутинга. Каждый пир (сервер - тоже пир) имеет пару открытый/закрытый ключ. Закрытый ключ остается у пира, открытый прописывается у его партнера. Каждый пир авторизует другого по знанию приватного ключа, соответствующего прописанному у него публичному ключу.
Протокол построен таким образом, что на все неправильные UDP пакеты не следует ответа.
Не знаешь приватный ключ? Не смог послать правильный запрос?
Долбись сколько влезет, я тебе ничего не отвечу. Это защищает от активного пробинга со стороны DPI и просто экономит ресурсы.
Значит, первым делом нужно создать 2 пары ключей: для сервера и для клиента.
`wg genkey` генерит приватный ключ, `wg pubkey` получает из него публичный ключ.

```sh
$ wg genkey
oAUkmhoREtFQ5D5yZmeHEgYaSWCcLYlKe2jBP7EAGV0=
$ echo oAUkmhoREtFQ5D5yZmeHEgYaSWCcLYlKe2jBP7EAGV0= | wg pubkey
bCdDaPYSTBZVO1HTmKD+Tztuf3PbOWGDWfz7Lb1E6C4=
$ wg genkey
OKXX0TSlyjJmGt3/yHlHxi0AqjJ0vh+Msne3qEHk0VM=
$ echo OKXX0TSlyjJmGt3/yHlHxi0AqjJ0vh+Msne3qEHk0VM= | wg pubkey
EELdA2XzjcKxtriOCPBXMOgxlkgpbRdIyjtc3aIpkxg=
```

Пишем конфиг:

`/etc/wireguard/wgvps.conf`:

```conf
[Interface]
PrivateKey = OKXX0TSlyjJmGt3/yHlHxi0AqjJ0vh+Msne3qEHk0VM=
ListenPort = 12345

[Peer]

# Endpoint =
PublicKey = bCdDaPYSTBZVO1HTmKD+Tztuf3PbOWGDWfz7Lb1E6C4=
AllowedIPs = 192.168.254.3
PersistentKeepalive=20
```

WireGuard - минималистичный VPN. В нем нет никаких средств для автоконфигурации IP.
Все придется прописывать руками.
В `wgvps.conf` должны быть перечислены все пиры с их публичными ключами, а так же прописаны допустимые для них IP адреса.
Назначим нашему клиенту 192.168.254.3. Сервер будет иметь IP 192.168.254.1.
Endpoint должен быть прописан хотя бы на одном пире.
Если endpoint настроен для пира, то WireGuard будет периодически пытаться к нему подключиться.
В схеме клиент/сервер у сервера можно не прописывать endpoint-ы пиров, что позволит менять IP и быть за NAT.
Endpoint пира настраивается динамически после успешной фазы проверки ключа.

Включаем маршрутизацию:

```sh
echo net.ipv4.ip_forward = 1 >>/etc/sysctl.conf
sysctl -p
```

Интерфейс конфигурируется стандартно для дебиан-подобных систем:

`/etc/network/interfaces.d/wgvps`:

```
auto wgvps
iface wgvps inet static
        address 192.168.254.1
        netmask 255.255.255.0
        pre-up ip link add $IFACE type wireguard
        pre-up wg setconf $IFACE /etc/wireguard/$IFACE.conf
        post-up iptables -t nat -A POSTROUTING -o eth0 -s 192.168.254.0/24 -j MASQUERADE
        post-up iptables -A FORWARD -o eth0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        post-down iptables -D FORWARD -o eth0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        post-down iptables -t nat -D POSTROUTING -o eth0 -s 192.168.254.0/24 -j MASQUERADE
        post-down ip link del $IFACE
```

Поднятие через `ifup wgvps`, опускание через `ifdown wgvps`.
При поднятии интерфейса заодно настраивается NAT. `eth0` здесь означает интерфейс VPN сервера с инетовским IP адресом.
Если у вас какая-то система управления фаерволом, то надо настройку NAT прикручивать туда.
Пример написан для простейшего случая, когда никаких ограничений нет, таблицы `iptables` пустые.
Чтобы посмотреть текущие настройки WireGuard, запустите `wg` без параметров.

Поднятие клиента:

```sh
opkg update
opkg install wireguard-tools
```

Добавляем записи в конфиги:

`/etc/config/network`:

```
config interface 'wgvps'
        option proto 'wireguard'
        option auto '1'
        option private_key 'oAUkmhoREtFQ5D5yZmeHEgYaSWCcLYlKe2jBP7EAGV0='
        option listen_port '12345'
        option metric '9'
        option mtu '1420'

config wireguard_wgvps
        option public_key 'EELdA2XzjcKxtriOCPBXMOgxlkgpbRdIyjtc3aIpkxg='
        list allowed_ips '0.0.0.0/0'
        option endpoint_host '91.15.68.202'
        option endpoint_port '12345'
        option route_allowed_ips '0'
        option persistent_keepalive '20'

config interface 'wgvps_ip'
        option proto 'static'
        option ifname '@wgvps'
        list ipaddr '192.168.254.3/24'

config route
        option interface 'wgvps'
        option target '0.0.0.0/0'
        option table '100'

config rule
        option mark '0x800/0x800'
        option priority '100'
        option lookup '100'
```

`/etc/config/firewall`:

```
config zone
        option name 'tunvps'
        option output 'ACCEPT'
        option input 'REJECT'
        option masq '1'
        option mtu_fix '1'
        option forward 'REJECT'
        option network 'wgvps wgvps_ip'

config forwarding
        option dest 'tunvps'
        option src 'lan'

config rule
        option name 'Allow-ICMP-tunvps'
        option src 'tunvps'
        option proto 'icmp'
        option target 'ACCEPT'

config rule
        option target 'ACCEPT'
        option src 'wan'
        option proto 'udp'
        option family 'ipv4'
        option src_port '12345'
        option src_ip '91.15.68.202'
        option name 'WG-VPS'
```

Что тут было сделано:

- Настроен интерфейс `wireguard`. Указан собственный приватный ключ.
- Настроен пир-партнер с указанием его публичного ключа и endpoint (IP:port нашего сервера)
  - Такая настройка заставит периодически долбиться на сервер по указанному IP
  - `route_allowed_ip '0'` запрещает автоматическое создание маршрута
  - `allowed_ips '0.0.0.0/0'` разрешает пакеты с любым адресом источника, ведь мы собираемся подключаться к любым IP в инете
  - `persistent_keepalive '20'` помогает исключить дропание mapping на NAT-е, если мы сидим за ним, да и вообще полезная вещь, чтобы не было подвисших пиров
- Статическая конфигурация IP интерфейса `wgvps`.
- Маршрут `default route` на `wgvps` в отдельной таблице маршрутизации с номером 100. Аналог команды `ip route add .. table 100`
- Правило использовать таблицу 100 при выставлении в mark бита 0x800. Аналог команды `ip rule`.
- Отдельная зона фаервола для VPN - `tunvps`. В принципе, ее можно не создавать, можете приписать интерфейс к зоне `wan`.

Но в случае с отдельной зоной можно настроить особые правила на подключения с VPN сервера в сторону клиента.

- Разрешение форвардинга между локалкой за роутером и `wgvps`.
- Разрешение принимать ICMP от VPN сервера, включая пинги. ICMP жизненно важны для правильного функционирования IP сети!
- И желательно проткнуть дырку в фаерволе, чтобы принимать пакеты WireGuard со стороны инетовского IP VPN сервера.

Конечно, оно скорее всего заработает и так, потому что первый пакет пойдет от клиента к серверу и тем самым создаст запись в conntrack.
Все дальнейшие пакеты в обе стороны подпадут под состояние ESTABLISHED и будут пропущены.
Запись будет поддерживаться за счет периодических запросов keep alive.
Но если вы вдруг уберете keep alive или выставите таймаут, превышающий UDP таймаут в conntrack, то могут начаться ошибки, висы и переподключения.
Если же в фаерволе проткнута дырка, то пакеты от сервера не будут заблокированы ни при каких обстоятельствах.

Перезапускаем фаерволл, поднимаем интерфейс и проверяем:

```sh
/etc/init.d/firewall restart
ifup wgvps
ifconfig wgvps
ping 192.168.254.1
```

Если все хорошо, должны ходить пинги.
С сервера не помешает :

```sh
ping 192.168.254.3
```

# Подготовка `zapret`

Выполните `install_easy.sh`. Он настроит режим обхода DPI. Если обход DPI не нужен - выберите `MODE=filter`.
Так же инсталлятор заресолвит домены из `ipset/zapret-hosts-user-ipban.txt` и внесет крон-джоб для периодического обновления IP.

Если вы используете в своих правилах ipset zapret, то он ресолвится и обновляется только, если выбран режим фильтрации обхода DPI по ipset.
По сути он вам нужен исключительно, если обход DPI не помогает. Например, удается как-то пробить HTTP, но не удается пробить HTTPS.
И при этом вы хотите, чтобы на VPN направлялись только IP из скачанного IP листа, в добавок к заресолвленному `ipset/zapret-hosts-user.txt`.
Именно этот случай и рассмотрен в данном примере. Если это не так, то убирайте правила с портом 443 из нижеприведенных правил `iptables`/`nftables`.
Если не хотите ограничиваться листом, и хотите направлять все на порт 443, то уберите фильтры из правил `iptables`/`nftables`, связанные с `ipset`/`nfset` "zapret".

Фильтрация по именам доменов (`MODE_FILTER=hostlist`) невозможна средствами `iptables`/`nftables`. Она производится исключительно в `tpws` и `nfqws` по результатам анализа протокола прикладного уровня, иногда достаточно сложного, связанного с дешифровкой пакета (QUIC).
Скачиваются листы с именами доменов, не IP адресами. `ipset/zapret-hosts-user.txt` не ресолвится, а используется как hostlist.
Потому вам нельзя рассчитывать на ipset zapret.
Тем не менее, при выборе этого режима фильтрации, либо вовсе при ее отсутствии (`MODE_FILTER=none`), `ipset/zapret-hosts-user-ipban.txt` все равно ресолвится.
Вы всегда можете рассчитывать на `ipset`/`nfset` "ipban", "nozapret".

"nozapret" - это `ipset`/`nfset`, связанный с системой исключения IP. Сюда загоняется все из `ipset/zapret-hosts-user-exclude.txt` после ресолвинга.
Его учет крайне желателен, чтобы вдруг из скачанного листа не просочились записи, например, 192.168.0.0/16 и не заставили лезть туда через VPN.
Хотя скрипты получения листов и пытаются отсечь IP локалок, но так будет намного надежнее.

## Маркировка трафика `iptables`

Завернем на VPN все из ipset zapret на TCP:443 и все из `ipban`.
OUTPUT относится к исходящим с роутера пакетам, PREROUTING - ко всем остальным.
Если с самого роутера ничего заруливать не надо, можно опустить часть, отвечающую за OUTPUT.

`/etc/firewall.user`:

```sh
. /opt/zapret/init.d/openwrt/functions

create_ipset no-update

network_find_wan4_all wan_iface
for ext_iface in $wan_iface; do
    network_get_device DEVICE $ext_iface
    ipt OUTPUT -t mangle -o $DEVICE -p tcp --dport 443 -m set --match-set zapret dst -m set ! --match-set nozapret dst -j MARK --set-mark 0x800/0x800
    ipt OUTPUT -t mangle -o $DEVICE -m set --match-set ipban dst -m set ! --match-set nozapret dst -j MARK --set-mark 0x800/0x800
done

network_get_device DEVICE lan
ipt PREROUTING -t mangle -i $DEVICE -p tcp --dport 443 -m set --match-set zapret dst -m set ! --match-set nozapret dst -j MARK --set-mark 0x800/0x800
ipt PREROUTING -t mangle -i $DEVICE -m set --match-set ipban dst -m set ! --match-set nozapret dst -j MARK --set-mark 0x800/0x800
```

```sh
/etc/init.d/firewall restart
```

## Маркировка трафика `nftables`

В новых OpenWrt по умолчанию установлен `nftables`, `iptables` отсутствует.
Есть вариант снести `nftables` + `fw4` и заменить их на `iptables` + `fw3`.
Веб-интерфейс luci понимает прозрачно и `fw3`, и `fw4`. Однако, при установке `iptables` и `fw3` новые пакеты будут устанавливаться без сжатия squashfs. Убедитесь, что у вас достаточно места.
Либо сразу настраивайте образ через image builder.

Фаервол `fw4` работает в одноименной nftable - "inet fw4". "inet" означает, что таблица принимает и IPv4, и IPv6.
Поскольку для маркировки трафика используется `nfset`, принадлежащий таблице zapret, цепочки необходимо помещать в ту же таблицу.
Для синхронизации лучше всего использовать хук `INIT_FW_POST_UP_HOOK="/etc/firewall.zapret.hook.post_up"`
Параметр нужно раскомментировать в `/opt/zapret/config`. Далее надо создать указанный файл и дать ему `chmod 755`.

`/etc/firewall.zapret.hook.post_up`:

```sh
# !/bin/sh

ZAPRET_NFT_TABLE=zapret

cat << EOF | nft -f - 2>/dev/null
    delete chain inet $ZAPRET_NFT_TABLE my_output
    delete chain inet $ZAPRET_NFT_TABLE my_prerouting
EOF

cat << EOF | nft -f -
    add chain inet $ZAPRET_NFT_TABLE my_output { type route hook output priority mangle; }
    flush chain inet $ZAPRET_NFT_TABLE my_output
    add rule inet $ZAPRET_NFT_TABLE my_output oifname @wanif ip daddr @ipban ip daddr != @nozapret meta mark set mark or 0x800
    add rule inet $ZAPRET_NFT_TABLE my_output oifname @wanif tcp dport 443 ip daddr @zapret ip daddr != @nozapret meta mark set mark or 0x800
    add chain inet $ZAPRET_NFT_TABLE my_prerouting { type filter hook prerouting priority mangle; }
    flush chain inet $ZAPRET_NFT_TABLE my_prerouting
    add rule inet $ZAPRET_NFT_TABLE my_prerouting iifname @lanif ip daddr @ipban ip daddr != @nozapret meta mark set mark or 0x800
    add rule inet $ZAPRET_NFT_TABLE my_prerouting iifname @lanif tcp dport 443 ip daddr @zapret ip daddr != @nozapret meta mark set mark or 0x800
EOF
```

```sh
/etc/init.d/zapret restart_fw
```

Проверка правил:

```sh
/etc/init.d/zapret list_table
# или
nft -t list table inet zapret
```

Должны быть цепочки `my_prerouting` и `my_output`.

Проверка заполнения nfsets:

```sh
nft list set inet zapret zapret
nft list set inet zapret ipban
nft list set inet zapret nozapret
```

Проверка заполнения множеств `lanif`, `wanif`, `wanif6`, `link_local`:

```sh
/etc/init.d/zapret list_ifsets
```

Должны присутствовать имена интерфейсов во множествах `lanif`, `wanif`.
`wanif6` заполняется только при включении IPv6.
`link_local` нужен только для tpws при включении IPv6.

## По поводу двойного NAT

В описанной конфигурации NAT выполняется дважды: на роутере-клиенте происходит замена адреса источника из LAN на 192.168.254.3 и на сервере замена 192.168.254.3 на внешний адрес сервера в инете.
Зачем так делать? Исключительно для простоты настройки. Или на случай, если сервер WireGuard не находится под вашим контролем.
Делать для вас нижеописанные настройки никто не будет с вероятностью, близкой к 100%.
Если сервер WireGuard - ваш, и вы готовы чуток еще поднапрячься и не хотите двойного NAT,
то можете вписать в `/etc/config/firewall` `masq '0'`, на сервер дописать маршрут до вашей подсети LAN.
Чтобы не делать это для каждого клиента, можно отвести под всех клиентов диапазон 192.168.0.0-192.168.127.255
и прописать его одним маршрутом:

`/etc/network/interfaces.d/wgvps`:

```
        post-up ip route add dev $IFACE 192.168.0.0/17
        post-down ip route del dev $IFACE 192.168.0.0/17
```

Также необходимо указать WireGuard дополнительные разрешенные IP для peer:

`/etc/wireguard/wgvps.conf`:

```
[Peer]
PublicKey = bCdDaPYSTBZVO1HTmKD+Tztuf3PbOWGDWfz7Lb1E6C4=
AllowedIPs = 192.168.254.3, 192.168.2.0/24
```

Всем клиентам придется назначать различные диапазоны адресов в LAN и индивидуально прописывать `AllowedIPs`
для каждого peer.

```sh
ifdown wgvps
ifup wgvps
```

На клиенте разрешим форвард ICMP, чтобы работал пинг и корректно определялось MTU.

`/etc/config/firewall`:

```
config rule
        option name 'Allow-ICMP-tunvps'
        option src 'tunvps'
        option dest 'lan'
        option proto 'icmp'
        option target 'ACCEPT'
```

Существуют еще два неочевидных нюанса.

Первый из них касается пакетов с самого роутера (цепочка OUTPUT).
Адрес источника выбирается по особому алгоритму, если программа явно его не задала, еще до этапа `iptables`.
Он берется с интерфейса, куда бы пошел пакет при нормальном раскладе.
Обратная маршрутизация с VPN станет невозможной, да и WireGuard такие пакеты порежет, поскольку они не вписываются в `AllowedIPs`.
Никаким мистическим образом автоматом source address не поменяется.
В прошлом варианте настройки проблема решалось через маскарад. Сейчас же маскарада нет.
Потому все же придется его делать в случае, когда пакет изначально направился бы через WAN,
а мы его завертываем на VPN. Помечаем такие пакеты марком 0x1000.
Если вам не актуальны исходящие с самого роутера, то можно ничего не менять.

Другой нюанс связан с обработкой проброшенных на VPS портов, соединения по которым приходят как входящие с интерфейса `wgvps`.
Представьте себе, что вы пробросили порт 2222. Кто-то подключается с адреса 1.2.3.4. Вам приходит пакет SYN 1.2.3.4:51723=>192.168.2.2:2222.
По правилам маршрутизации он пойдет в локалку. 192.168.2.2 его обработает, ответит пакетом ACK 192.168.2.2:2222=>1.2.3.4:51723.
Этот пакет придет на роутер. И куда он дальше пойдет? Если он не занесен в ipban, то согласно правилам маршрутизации
он пойдет по WAN интерфейсу, а не по исходному `wgvps`.
Чтобы решить эту проблему, необходимо воспользоваться CONNMARK. Существуют 2 отдельных марка: fwmark и connmark.
connmark относится к соединению, fwmark - к пакету. Трэкингом соединений занимается conntrack.
Посмотреть его таблицу можно командой `conntrack -L`. Там же найдете connmark: mark=xxxx.
Как только видим приходящий с `wgvps` пакет с новым соединением, отмечаем его connmark как 0x800/0x800.
При этом fwmark не меняется, иначе бы пакет тут же бы завернулся обратно на `wgvps` согласно `ip rule`.
Если к нам приходит пакет с какого-то другого интерфейса, то восстанавливаем его connmark в fwmark по маске 0x800.
И теперь он подпадает под правило `ip rule`, заворачиваясь на `wgvps`, что и требовалось.

Альтернативное решение - использовать на VPSке для проброса портов не только DNAT, но и SNAT/MASQUERADE.
Тогда source address будет заменен на 192.168.254.1. Он по таблице маршрутизации пойдет на wgvps.
Но в этом случае клиентские программы, на которые осуществляется проброс портов, не будут видеть реальный IP подключенца.

`/etc/firewall.user`:

```sh
. /opt/zapret/init.d/openwrt/functions

create_ipset no-update

network_find_wan4_all wan_iface
for ext_iface in $wan_iface; do
    network_get_device DEVICE $ext_iface
    ipt OUTPUT -t mangle -o $DEVICE -p tcp --dport 443 -m set --match-set zapret dst -m set ! --match-set nozapret dst -j MARK --set-mark 0x800/0x800
    ipt OUTPUT -t mangle -o $DEVICE -m set --match-set ipban dst -m set ! --match-set nozapret dst -j MARK --set-mark 0x800/0x800
    ipt OUTPUT -t mangle -o $DEVICE -j MARK --set-mark 0x1000/0x1000
done

network_get_device DEVICE lan
ipt PREROUTING -t mangle -i $DEVICE -p tcp --dport 443 -m set --match-set zapret dst -m set ! --match-set nozapret dst -j MARK --set-mark 0x800/0x800
ipt PREROUTING -t mangle -i $DEVICE -m set --match-set ipban dst -m set ! --match-set nozapret dst -j MARK --set-mark 0x800/0x800

# do masquerade for OUTPUT to ensure correct outgoing address

ipt postrouting_tunvps_rule -t nat -m mark --mark 0x1000/0x1000 -j MASQUERADE

# incoming from wgvps

network_get_device DEVICE wgvps
ipt PREROUTING -t mangle ! -i $DEVICE -j CONNMARK --restore-mark --nfmask 0x800 --ctmask 0x800
ipt PREROUTING -t mangle -i $DEVICE -m conntrack --ctstate NEW -j CONNMARK --set-mark 0x800/0x800
```

```sh
/etc/init.d/firewall restart
```

Вариант `nftables`:

`/etc/firewall.zapret.hook.post_up`:

```sh
# !/bin/sh

ZAPRET_NFT_TABLE=zapret
DEVICE=wgvps

cat << EOF | nft -f - 2>/dev/null
 delete chain inet $ZAPRET_NFT_TABLE my_output
 delete chain inet $ZAPRET_NFT_TABLE my_prerouting
 delete chain inet $ZAPRET_NFT_TABLE my_nat
EOF

cat << EOF | nft -f -
 add chain inet $ZAPRET_NFT_TABLE my_output { type route hook output priority mangle; }
 flush chain inet $ZAPRET_NFT_TABLE my_output
 add rule inet $ZAPRET_NFT_TABLE my_output oifname @wanif ip daddr @ipban ip daddr != @nozapret meta mark set mark or 0x800
 add rule inet $ZAPRET_NFT_TABLE my_output oifname @wanif tcp dport 443 ip daddr @zapret ip daddr != @nozapret meta mark set mark or 0x800
 add rule inet $ZAPRET_NFT_TABLE my_output oifname @wanif meta mark set mark or 0x1000

 add chain inet $ZAPRET_NFT_TABLE my_prerouting { type filter hook prerouting priority mangle; }
 flush chain inet $ZAPRET_NFT_TABLE my_prerouting
 add rule inet $ZAPRET_NFT_TABLE my_prerouting iifname $DEVICE ct state new ct mark set ct mark or 0x800
 add rule inet $ZAPRET_NFT_TABLE my_prerouting iifname != $DEVICE meta mark set ct mark and 0x800
 add rule inet $ZAPRET_NFT_TABLE my_prerouting iifname @lanif ip daddr @ipban ip daddr != @nozapret meta mark set mark or 0x800
 add rule inet $ZAPRET_NFT_TABLE my_prerouting iifname @lanif tcp dport 443 ip daddr @zapret ip daddr != @nozapret meta mark set mark or 0x800

add chain inet $ZAPRET_NFT_TABLE my_nat { type nat hook postrouting priority 100 ; }
 flush chain inet $ZAPRET_NFT_TABLE my_nat
 add rule inet $ZAPRET_NFT_TABLE my_nat oifname $DEVICE mark and 0x1000 == 0x1000 masquerade
EOF
```

```sh
/etc/init.d/zapret restart_fw
```

К сожалению, здесь возможности `nftables` немного хромают. Полноценного эквивалента `CONNMARK --restore-mark --nfmask` не существует. Оригинал `iptables` предполагал копирование одного бита 0x800 из connmark в mark.
Лучшее, что можно сделать в `nftables`, это копирование одного бита с занулением всех остальных.
Сложные выражения типа `meta mark set mark and ~0x800 or (ct mark and 0x800)` nft не понимает.
Об этом же говорит попытка перевода через `iptables-translate`.

Сейчас уже можно с VPN сервера пингануть IP адрес внутри локалки клиента. Пинги должны ходить.

Отсутствие двойного NAT значительно облегчает проброс портов с внешнего IP VPN сервера в локалку какого-либо клиента.
Для этого надо выполнить 2 действия: добавить разрешение в фаервол на клиенте и сделать dnat на сервере.
Пример форварда портов 5001 и 5201 на 192.168.2.2 :

`/etc/config/firewall`:

```
config rule
        option target 'ACCEPT'
        option src 'tunvps'
        option dest 'lan'
        option proto 'tcp udp'
        option dest_port '5001 5201'
        option dest_ip '192.168.2.2'
        option name 'IPERF'
```

```sh
/etc/init.d/firewall restart
/etc/init.d/zapret restart_fw
```

`/etc/network/interfaces.d/wgvps`:

```
 post-up iptables -t nat -A PREROUTING -i eth0 -p tcp -m multiport --dports 5001,5201 -j DNAT --to-destination 192.168.2.2
 post-up iptables -t nat -A PREROUTING -i eth0 -p udp -m multiport --dports 5001,5201 -j DNAT --to-destination 192.168.2.2
 post-down iptables -t nat -D PREROUTING -i eth0 -p tcp -m multiport --dports 5001,5201 -j DNAT --to-destination 192.168.2.2
 post-down iptables -t nat -D PREROUTING -i eth0 -p udp -m multiport --dports 5001,5201 -j DNAT --to-destination 192.168.2.2
```

```sh
ifdown wgvps
ifup wgvps
```

Пример приведен для `iperf` и `iperf3`, чтобы показать как пробрасывать несколько портов TCP+UDP с минимальным количеством команд.
Проброс TCP и UDP порта так же необходим для полноценной работы bittorrent клиента, чтобы работали входящие.

# Как мне отправлять на VPN весь трафик с bittorrent?

Можно поступить так: посмотрите порт в настройках torrent клиента, убедитесь, что не поставлено "случайный порт", добавьте на роутер правило маркировки по порту источника.
Но мне предпочтительно иное решение. На Windows есть замечательная возможность прописать правило установки поля качества обслуживания в заголовках IP пакетов в зависимости от процесса-источника.
Для Windows 7/2008R2 необходимо будет установить ключик реестра и перезагрузить комп :

```powershell
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\QoS /v "Do not use NLA" /t REG_SZ /d "1"
```

Редактировать политику можно в: `gpedit.msc` -> Computer Configuration -> Windows Settings -> Policy-based QoS
На Windows 10 ключик реестра больше не работает, правила qos в `gpedit` применяются только для профиля домена.
Необходимо пользоваться командой `powershell New-NetQosPolicy`. Гуглите хелп по ней. Пример :

```powershell
powershell New-NetQosPolicy -Name "torrent" -AppPathNameMatchCondition "qbittorrent.exe" -DSCPAction 1
```

Однозначно требуется проверка в WireShark или netmon успешности установки поля `dscp`. Если там по-прежнему 0x00, значит, что-то не сработало. 0x04 означает `DSCP=1` (dscp находится в старших 6 битах).

На роутере в фаервол прописываем правило:

`/etc/config/firewall`:

```
config rule
        option target 'MARK'
        option src 'lan'
        option proto 'all'
        option extra '-m dscp --dscp 1'
        option name 'route-dscp-1'
        option set_mark '0x0800/0x0800'
```

```sh
/etc/init.d/firewall restart
```

Теперь все с полем dscp "1" идет на VPN. Клиент сам решает какой трафик ему нужно забрасывать
на VPN, перенастраивать роутер не нужно.
На Linux клиенте проще всего будет выставлять dscp в `iptables` по номеру порта источника :

`/etc/rc.local`:

```sh
iptables -A OUTPUT -t mangle -p tcp --sport 23444 -j DSCP --set-dscp 1
iptables -A OUTPUT -t mangle -p udp --sport 23444 -j DSCP --set-dscp 1
```

Можно привязываться к pid процесса, но тогда нужно перенастраивать `iptables` при каждом перезапуске
торрент-клиента, это требует рута, и все становится очень неудобно.

## Автоматизация проброса портов через `miniupnd`

Да, его тоже можно использовать на VPS. Только, как всегда, есть нюансы.

`miniupnpd` поддерживает 3 протокола IGD: UPnP, NAT-PMP и PCP.
UPnP и PCP работают через мультикаст, который не пройдет через wgvps.
NAT-PMP работает через посылку специальных сообщений на UDP:5351 на default gateway.
Обычно их обслуживает `miniupnpd` на роутере. При создании lease `miniupnpd` добавляет
правила для проброса портов в цепочку `iptables MINIUPNPD`, при потери lease - убирает.

UDP:5351 можно перенаправить на VPN сервер через DNAT, чтобы их обрабатывал `miniupnpd` там.
Но вы должны иметь однозначный критерий перенаправления.
Если вы решили завернуть на VPN все, то проблем нет. Пробрасываем UDP:5351 безусловно.
Если у вас идет перенаправление только с торрент, то необходимо к условию перенаправления добавить условия, выделяющие torrent трафик из прочего. Или по dscp, или по sport.
Чтобы запросы от остальных программ обрабатывались miniupnpd на роутере.
Если какая-то программа создаст lease не там, где нужно, то входящий трафик до нее не дойдет.

На роутере стоит запретить протокол UPnP, чтобы торрент клиент не удовлетворился запросом, обслуженным по UPnP на роутере, и пытался использовать NAT-PMP.

`/etc/config/upnp`:

```
config upnpd 'config'
        .....
        option enable_upnp '0'
```

```sh
/etc/init.d/miniupnpd restart
```

Делаем проброс порта на роутере.
Для простоты изложения будем считать, что на VPN у нас завернут весь трафик.
Если это не так, то следует добавить фильтр в "config redirect".
Заодно выделяем диапазон портов для торрент клиентов.
Порт в торрент клиенте следует прописать какой-то из этого диапазона.

```
config redirect
        option enabled '1'
        option target 'DNAT'
        option src 'lan'
        option dest 'tunvps'
        option proto 'udp'
        option src_dport '5351'
        option dest_ip '192.168.254.1'
        option dest_port '5351'
        option name 'NAT-PMP'
        option reflection '0'
config rule
        option enabled '1'
        option target 'ACCEPT'
        option src 'tunvps'
        option dest 'lan'
        option name 'tunvps-torrent'
        option dest_port '28000-28009'
```

```sh
/etc/init.d/firewall reload
```

На сервере:

```sh
apt install miniupnpd
```

`/etc/miniupnpd/miniupnpd.conf`:

```conf
enable_natpmp=yes
enable_upnp=no
lease_file=/var/log/upnp.leases
system_uptime=yes
clean_ruleset_threshold=10
clean_ruleset_interval=600
force_igd_desc_v1=no
listening_ip=192.168.254.1/16
ext_ifname=eth0
```

```sh
systemctl restart miniupnpd
```

`listening_ip` прописан именно таким образом, чтобы обозначить диапазон разрешенных IP.
С других IP он не будет обрабатывать запросы на редирект.
В `ext_ifname` впишите название `inet` интерфейса на сервере.

Запускаем торрент клиент. Попутно смотрим в `tcpdump` весь путь UDP:5351 до сервера и обратно.
Смотрим `syslog` сервера на ругань от miniupnpd.
Если все ок, то можем проверить редиректы: `iptables -t nat -nL MINIUPNPD`
С какого-нибудь другого хоста (не VPN сервер, не ваше подключение) можно попробовать `telnet`-нуться на проброшенный порт.
Должно установиться соединение. Или качайте торрент и смотрите в пирах флаг "I" (incoming).
Если "I" есть и по ним идет закачка, значит все в порядке.

**ОСОБЕННОСТЬ НОВЫХ DEBIAN:** по умолчанию используются `iptables-nft`. miniupnpd работает с `iptables-legacy`.
**ЛЕЧЕНИЕ:** `update-alternatives --set iptables /usr/sbin/iptables-legacy`
