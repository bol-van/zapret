- [Пример ручной установки на Debian-подобную систему](#пример-ручной-установки-на-debian-подобную-систему)
- [CentOS 7+, Fedora](#centos-7-fedora)
- [openSUSE](#opensuse)
- [Arch Linux](#arch-linux)
- [Gentoo](#gentoo)
- [Ручная установка на OpenWrt/LEDE 15.xx-21.xx](#ручная-установка-на-openwrtlede-15xx-21xx)

Пример ручной установки на Debian-подобную систему
--------------------------------------------------

На Debian основано большое количество дистрибутивов Linux, включая Ubuntu.
Здесь рассматриваются прежде всего Debian 8+ и Ubuntu 16+.
Но с большой вероятностью может сработать и на производных от них.
Главное условие - наличие `systemd`, `apt` и нескольких стандартных пакетов в репозитории.

Установить пакеты:

```sh
apt-get update
apt-get install ipset curl dnsutils git
```

Если хотите использовать `nftables`, то нужен пакет `nftables`, а `ipset` не обязателен.

Скопировать директорию `zapret` в `/opt` или скачать через `git`:

```sh
cd /opt
git clone --depth 1 https://github.com/bol-van/zapret
```

Запустить автоинсталлятор бинарников. Он сам определит рабочую архитектуру и настроит все бинарники.

```sh
/opt/zapret/install_bin.sh
```

**АЛЬТЕРНАТИВА:** `make -C /opt/zapret`. Получите динамические бинарники под вашу ось.
Для сборки требуются dev пакеты: `zlib1g-dev`, `libcap-dev`, `libnetfilter-queue-dev`.

Создать конфиг по умолчанию:

```sh
cp /opt/zapret/config.default /opt/zapret/config
```

Настроить параметры согласно разделу "Выбор параметров".

Создать user листы по умолчанию:

```sh
cp /opt/zapret/ipset/zapret-hosts-user-exclude.txt.default /opt/zapret/ipset/zapret-hosts-user-exclude.txt
echo nonexistent.domain > /opt/zapret/ipset/zapret-hosts-user.txt
touch /opt/zapret/ipset/zapret-hosts-user-ipban.txt
```

Создать ссылку на service unit в `systemd`:

```sh
ln -fs /opt/zapret/init.d/systemd/zapret.service /lib/systemd/system
```

Удалить старые листы, если они были созданы ранее:

```sh
/opt/zapret/ipset/clear_lists.sh
```

По желанию прописать в `/opt/zapret/ipset/zapret-hosts-user.txt` свои домены.

Выполнить скрипт обновления листа:

```sh
/opt/zapret/ipset/get_config.sh
```

Настроить таймер `systemd` для обновления листа:

```sh
ln -fs /opt/zapret/init.d/systemd/zapret-list-update.service /lib/systemd/system
ln -fs /opt/zapret/init.d/systemd/zapret-list-update.timer /lib/systemd/system
```

Принять изменения в `systemd`: `systemctl daemon-reload`

Включить автозапуск службы: `systemctl enable zapret`

Включить таймер обновления листа: `systemctl enable zapret-list-update.timer`

Запустить службу: `systemctl start zapret`

Шпаргалка по управлению службой и таймером :

- enable auto start: `systemctl enable zapret`
- disable auto start: `systemctl disable zapret`
- start: `systemctl start zapret`
- stop: `systemctl stop zapret`
- status, output messages: `systemctl status zapret`
- timer info: `systemctl list-timer`
- delete service: `systemctl disable zapret; rm /lib/systemd/system/zapret.service`
- delete timer: `systemctl disable zapret-list-update.timer; rm /lib/systemd/system/zapret-list-update.*`

CentOS 7+, Fedora
-----------------

CentOS с 7 версии и более-менее новые федоры построены на `systemd`.
В качестве пакетного менеджера используется `yum`.

Установить пакеты:

```sh
yum install -y curl ipset dnsutils git
```

Далее все аналогично Debian.

openSUSE
--------

Новые openSUSE основаны на `systemd` и менеджере пакетов `zypper`.

Установить пакеты:

```sh
zypper --non-interactive install curl ipset
```

Далее все аналогично Debian, кроме расположения `systemd`.
В openSUSE он находится не в `/lib/systemd`, а в `/usr/lib/systemd`.
Правильные команды будут:

```sh
ln -fs /opt/zapret/init.d/systemd/zapret.service /usr/lib/systemd/system
ln -fs /opt/zapret/init.d/systemd/zapret-list-update.service /usr/lib/systemd/system
ln -fs /opt/zapret/init.d/systemd/zapret-list-update.timer /usr/lib/systemd/system
```

Arch Linux
----------

Построен на базе `systemd`.

Установить пакеты:

```sh
pacman -Syy
pacman --noconfirm -S ipset curl
```

Далее все аналогично Debian.

Gentoo
------

Эта система использует OpenRC - улучшенную версию sysvinit.
Установка пакетов производится командой: `emerge <package_name>`
Пакеты собираются из исходников.

Требуются все те же `ipset`, `curl`, `git` для скачивания с GitHub.
`git` и `curl` по умолчанию могут присутствовать, `ipset` отсутствует.

```sh
emerge ipset
```

Настроить параметры согласно разделу "Выбор параметров".

Запустить автоинсталлятор бинарников. Он сам определит рабочую архитектуру и настроит все бинарники:

```sh
/opt/zapret/install_bin.sh
```

**АЛЬТЕРНАТИВА:** `make -C /opt/zapret`. Получите динамические бинарники под вашу ось.

Удалить старые листы, если они были созданы ранее:

```sh
/opt/zapret/ipset/clear_lists.sh
```

По желанию прописать в `/opt/zapret/ipset/zapret-hosts-user.txt` свои домены.

Выполнить скрипт обновления листа:

```sh
/opt/zapret/ipset/get_config.sh
```

Зашедулить обновление листа:

```sh
crontab -e
```

Создать для крона строчку `0 12 */2* * /opt/zapret/ipset/get_config.sh`

Подключить init скрипт:

```sh
ln -fs /opt/zapret/init.d/openrc/zapret /etc/init.d
rc-update add zapret
```

Запустить службу:

```sh
rc-service zapret start
```

Шпаргалка по управлению службой:

- enable auto start: `rc-update add zapret`
- disable auto start: `rc-update del zapret`
- start: `rc-service zapret start`
- stop: `rc-service zapret stop`

Ручная установка на OpenWrt/LEDE 15.xx-21.xx
--------------------------------------------

**ВАЖНО:** Данная инструкция написана для систем, основанных на `iptables`+`firewall3`.
В новых версиях OpenWrt переходит на `nftables`+`firewall4`, инструкция неприменима. Пользуйтесь `install_easy.sh`

Установить дополнительные пакеты:

```sh
opkg update
opkg install iptables-mod-extra iptables-mod-nfqueue iptables-mod-filter iptables-mod-ipopt iptables-mod-conntrack-extra ipset curl
# (IPv6) opkg install ip6tables-mod-nat
# (опционально) opkg install gzip
# (опционально) opkg install coreutils-sort
```

**ЭКОНОМИЯ МЕСТА:**

`gzip` от `busybox` в разы медленней полноценного варианта. `gzip` используется скриптами получения листов.
`sort` от `busybox` медленней полноценного варианта и жрет намного больше памяти. `sort` используется скриптами получения листов.
`iptables-mod-nfqueue` можно выкинуть, если не будем пользоваться `nfqws`.
`curl` можно выкинуть, если для получения IP листа будет использоваться только `get_user.sh`

Самая главная трудность - скомпилировать программы на C. Это можно сделать на Linux x64 при помощи SDK, который можно скачать с официального сайта OpenWrt или LEDE. Но процесс кросс-компиляции - это всегда сложности.
Недостаточно запустить `make` как на традиционной Linux системе.
Поэтому в `binaries/` имеются готовые статические бинарники для всех самых распространенных архитектур.
Статическая сборка означает, что бинарник не зависит от типа `libc` (`glibc`, `uclibc` или `musl`) и наличия установленных `*.so`.
Его можно использовать сразу. Лишь бы подходил тип CPU. У ARM и MIPS есть несколько версий.
Скорее всего найдется рабочий вариант. Если нет - вам придется собирать самостоятельно.
Для всех поддерживаемых архитектур бинарники запакованы `upx`. На текущий момент все, кроме `mips64`.

Скопировать директорию `zapret` в `/opt` на роутер.

Если места достаточно, самый простой способ:

```sh
opkg update
opkg install git-http
mkdir /opt
cd /opt
git clone --depth 1 https://github.com/bol-van/zapret
```

Если места немного:

```sh
opkg update
opkg install openssh-sftp-server unzip
ifconfig br-lan
```

Скачать на комп с GitHub zip архив кнопкой "Clone or download" -> Download ZIP
Скопировать средствами `sftp` zip архив на роутер в `/tmp`.

```sh
mkdir /opt
cd /opt
unzip /tmp/zapret-master.zip
mv zapret-master zapret
rm /tmp/zapret-master.zip
```

Если места совсем мало:
На Linux системе скачать и распаковать zapret. Оставить необходимый минимум файлов.
Запаковать в архив `zapret.tar.gz`.

```sh
nc -l -p 1111 < zapret.tar.gz
```

На роутере:

```sh
cd /tmp
nc <linux_system_ip> 1111 >zapret.tar.gz
```

Не стоит работать с распакованной версией `zapret` на Windows. Потеряются ссылки и `chmod`.

Запустить автоинсталлятор бинарников. Он сам определит рабочую архитектуру и настроит все бинарники:

```sh
/opt/zapret/install_bin.sh
```

Создать ссылку на скрипт запуска:

```sh
ln -fs /opt/zapret/init.d/openwrt/zapret /etc/init.d
```

Создать ссылку на скрипт события поднятия интерфейса:

```sh
ln -fs /opt/zapret/init.d/openwrt/90-zapret /etc/hotplug.d/iface
```

Создать конфиг по умолчанию:

```sh
cp /opt/zapret/config.default /opt/zapret/config
```

Настроить параметры согласно разделу "Выбор параметров".

Создать user листы по умолчанию:

```sh
cp /opt/zapret/ipset/zapret-hosts-user-exclude.txt.default /opt/zapret/ipset/zapret-hosts-user-exclude.txt
echo nonexistent.domain > /opt/zapret/ipset/zapret-hosts-user.txt
touch /opt/zapret/ipset/zapret-hosts-user-ipban.txt
```

Удалить старые листы, если они были созданы ранее:

```sh
/opt/zapret/ipset/clear_lists.sh
```

По желанию прописать в `/opt/zapret/ipset/zapret-hosts-user.txt` свои домены.
Выполнить скрипт обновления листа:

```sh
/opt/zapret/ipset/get_config.sh
```

Зашедулить обновление листа:

```sh
crontab -e
```

Создать для крона строчку `0 12 */2* * /opt/zapret/ipset/get_config.sh`

Включить автозапуск службы и запустить ее:

```sh
/etc/init.d/zapret enable
/etc/init.d/zapret start
```

**ПРИМЕЧАНИЕ:** на этапе старта системы интерфейсы еще не подняты.
В некоторых случаях невозможно правильно сформировать параметры запуска демонов, не зная имя физического интерфейса LAN.
Скрипт из /etc/hotplug.d/iface перезапустит демоны по событию поднятия LAN.

Создать ссылку на firewall include:

```sh
ln -fs /opt/zapret/init.d/openwrt/firewall.zapret /etc/firewall.zapret
```

Проверить была ли создана ранее запись о firewall include:

```sh
uci show firewall | grep firewall.zapret
```

Если `firewall.zapret` нет, значит добавить:

```sh
uci add firewall include
uci set firewall.@include[-1].path="/etc/firewall.zapret"
uci set firewall.@include[-1].reload="1"
uci commit firewall
```

Проверить, не включен ли flow offload:

```sh
uci show firewall.@defaults[0]
```

Если `flow_offloading=1` или `flow_offloading_hw=1`:

```sh
uci set firewall.@defaults[0].flow_offloading=0
uci set firewall.@defaults[0].flow_offloading_hw=0
uci commit firewall
```

Перезапустить фаервол:

```sh
fw3 restart
```

Посмотреть через `iptables -nL`, `ip6tables -nL` или через `luci` вкладку "firewall", появились ли нужные правила.

**ЭКОНОМИЯ МЕСТА:** если его мало, то можно оставить в директории `zapret` лишь подкаталоги `ipset/`, `common/`, файл `config/`, `init.d/openwrt/`.
Далее нужно создать подкаталоги с реально используемыми бинарниками (`ip2net`, `mdig`, `tpws`, `nfq`) и скопировать туда из `binaries/` рабочие executables.

**ЕСЛИ ВСЕ ПЛОХО С МЕСТОМ:** откажитесь от работы со списком РКН. используйте только `get_user.sh`.

**ЕСЛИ СОВСЕМ ВСЕ УЖАСНО С МЕСТОМ:** берете `tpws` и делаете все своими руками. поднятие `iptables`, автостарт бинарника.
С некоторых версий скрипты запуска zapret без `ipset` не работают (он требуется для IP exclude).

**СОВЕТ:** Покупайте только роутеры с USB.
В USB можно воткнуть флэшку и вынести на нее корневую файловую систему или использовать ее в качестве оверлея.
Не надо мучить себя, запихивая незапихиваемое в 8 мб встроенной флэшки.
Для комфортной работы с zapret нужен роутер с 16 Mb встроенной памяти или USB разъемом и 128+ Mb RAM.
На 64 Mb без swap будут проблемы с листами РКН. Если у вас только 64 Mb, и вы хотите листы РКН, подключите swap.
32 Mb для современных версий OpenWrt - конфигурация на грани живучести. Возможны хаотические падения процессов в oom.
Работа с листами РКН невозможна в принципе.
