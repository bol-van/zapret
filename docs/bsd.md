- [Поддерживаемые версии](#поддерживаемые-версии)
- [Особенности BSD систем](#особенности-bsd-систем)
- [FreeBSD](#freebsd)
  - [Краткая инструкция по запуску `tpws` в прозрачном режиме](#краткая-инструкция-по-запуску-tpws-в-прозрачном-режиме)
- [pfsense](#pfsense)
- [OpenBSD](#openbsd)
- [macOS](#macos)
  - [Простая установка](#простая-установка)
  - [Вариант custom](#вариант-custom)

# Поддерживаемые версии

FreeBSD 11.x+, OpenBSD 6.x+, частично macOS Sierra+

На более старых может собираться, может не собираться, может работать или не работать.
На FreeBSD 10 собирается и работает `dvtws`. С `tpws` есть проблемы из-за слишком старой версии компилятора `clang`.
Вероятно, будет работать, если обновить компилятор.
Возможна прикрутка к последним версиям `pfsense` без веб-интерфейса в ручном режиме через консоль.

# Особенности BSD систем

В BSD нет nfqueue. Похожий механизм - divert sockets.
Из каталога `nfq/` под BSD собирается `dvtws` вместо `nfqws`.
Он разделяет с `nfqws` большую часть кода и почти совпадает по параметрам командной строки.

FreeBSD содержит 3 фаервола: IPFilter, `ipfw` и Packet Filter (PF). OpenBSD содержит только PF.

Под FreeBSD `tpws` и `dvtws` собираются через `make`, под OpenBSD - `make bsd`, под macOS - `make mac`.
FreeBSD `make` распознает `BSDmakefile`, OpenBSD и macOS - нет. Поэтому там используется отдельный `target` в `Makefile`.
Сборка всех исходников: `make -C /opt/zapret`

divert сокет - внутренний тип сокета ядра BSD. Он не привязывается ни к какому сетевому адресу, не участвует
в обмене данными через сеть и идентифицируется по номеру порта `1...65535`. Аналогия с номером очереди NFQUEUE.
На divert сокеты заворачивается трафик посредством правил `ipfw` или PF.
Если в фаерволе есть правило divert, но на divert порту никто не слушает, то пакеты дропаются.
Это поведение аналогично правилам NFQUEUE без параметра `--queue-bypass`.
На FreeBSD divert сокеты могут быть только IPv4, хотя на них принимаются и IPv4, и IPv6 фреймы.
На OpenBSD divert сокеты создаются отдельно для IPv4 и IPv6 и работают только с одной версией IP каждый.
На macOS похоже, что divert сокеты из ядра вырезаны. См. подробнее раздел про [macOS](#macos).
Отсылка в divert сокет работает аналогично отсылке через raw socket на Linux. Передается полностью IP фрейм, начиная с IP заголовка. Эти особенности учитываются в `dvtws`.

Скрипты `ipset/*.sh` при наличии `ipfw` работают с ipfw lookup tables.
Это прямой аналог `ipset`. lookup tables не разделены на v4 и v6. Они могут содержать v4 и v6 адреса и подсети одновременно.
Если `ipfw` отсутствует, то действие зависит от переменной `LISTS_RELOAD` в `config`.
Если она задана, то выполняется команда из `LISTS_RELOAD`. В противном случае не делается ничего.
Если `LISTS_RELOAD=-`, то заполнение таблиц отключается даже при наличии `ipfw`.

PF может загружать IP таблицы из файла. Чтобы использовать эту возможность следует отключить сжатие gzip для листов
через параметр файла `config` `GZIP_LISTS=0`.

BSD не содержит системного вызова `splice`. `tpws` работает через переброску данных в user mode в оба конца.
Это медленнее, но не критически.
Управление асинхронными сокетами в `tpws` основано на Linux-specific механизме epoll.
В BSD для его эмуляции используется epoll-shim - прослойка для эмуляции epoll на базе kqueue.

`mdig` и `ip2net` полностью работоспособны в BSD. В них нет ничего системозависимого.

# FreeBSD

divert сокеты требуют специального модуля ядра `ipdivert`.
Поместите следующие строки в `/boot/loader.conf` (создать, если отсутствует):

```conf
ipdivert_load="YES"
net.inet.ip.fw.default_to_accept=1
```

В `/etc/rc.conf`:

```conf
firewall_enable="YES"
firewall_script="/etc/rc.firewall.my"
```

`/etc/rc.firewall.my`:

```sh
ipfw -q -f flush
```

В `/etc/rc.firewall.my` можно дописывать правила `ipfw`, чтобы они восстанавливались после перезагрузки.
Оттуда же можно запускать и демоны `zapret`, добавив в параметры `--daemon`. Например, так:

```sh
pkill ^dvtws$
/opt/zapret/nfq/dvtws --port=989 --daemon --dpi-desync=split2
```

Для перезапуска фаервола и демонов достаточно будет сделать: `/etc/rc.d/ipfw restart`

## Краткая инструкция по запуску `tpws` в прозрачном режиме

Предполагается, что интерфейс LAN называется `em1`, WAN - `em0`.

Для всего трафика:

```sh
ipfw delete 100
ipfw add 100 fwd 127.0.0.1,988 tcp from me to any 80,443 proto ip4 xmit em0 not uid daemon
ipfw add 100 fwd ::1,988 tcp from me to any 80,443 proto ip6 xmit em0 not uid daemon
ipfw add 100 fwd 127.0.0.1,988 tcp from any to any 80,443 proto ip4 recv em1
ipfw add 100 fwd ::1,988 tcp from any to any 80,443 proto ip6 recv em1
/opt/zapret/tpws/tpws --port=988 --user=daemon --bind-addr=::1 --bind-addr=127.0.0.1
```

Для трафика только на таблицу `zapret`, за исключением таблицы `nozapret`:

```sh
ipfw delete 100
ipfw add 100 allow tcp from me to table\(nozapret\) 80,443
ipfw add 100 fwd 127.0.0.1,988 tcp from me to table\(zapret\) 80,443 proto ip4 xmit em0 not uid daemon
ipfw add 100 fwd ::1,988 tcp from me to table\(zapret\) 80,443 proto ip6 xmit em0 not uid daemon
ipfw add 100 allow tcp from any to table\(nozapret\) 80,443 recv em1
ipfw add 100 fwd 127.0.0.1,988 tcp from any to any 80,443 proto ip4 recv em1
ipfw add 100 fwd ::1,988 tcp from any to any 80,443 proto ip6 recv em1
/opt/zapret/tpws/tpws --port=988 --user=daemon --bind-addr=::1 --bind-addr=127.0.0.1
```

Таблицы `zapret`, `nozapret`, `ipban` создаются скриптами из `ipset` по аналогии с Linux.
Обновление скриптов можно забить в cron под root: `crontab -e`.
Создать для крона строчку `0 12 */2 * * /opt/zapret/ipset/get_config.sh`

При использовании `ipfw` `tpws` не требует повышенных привилегий для реализации прозрачного режима.
Однако, без рута невозможен бинд на порты <1024 и смена UID/GID. Без смены UID будет рекурсия,
поэтому правила `ipfw` нужно создавать с учетом UID, под которым работает `tpws`.
Переадресация на порты >=1024 может создать угрозу перехвата трафика непривилегированным
процессом, если вдруг `tpws` не запущен.

Краткая инструкция по запуску `dvtws`.

Для всего трафика:

```sh
ipfw delete 100
ipfw add 100 divert 989 tcp from any to any 80,443 out not diverted xmit em0

# required for autottl mode only

ipfw add 100 divert 989 tcp from any 80,443 to any tcpflags syn,ack in not diverted recv em0
/opt/zapret/nfq/dvtws --port=989 --dpi-desync=split2

Для трафика только на таблицу zapret, за исключением таблицы nozapret :
ipfw delete 100
ipfw add 100 allow tcp from me to table\(nozapret\) 80,443
ipfw add 100 divert 989 tcp from any to table\(zapret\) 80,443 out not diverted not sockarg xmit em0

# required for autottl mode only

ipfw add 100 divert 989 tcp from table\(zapret\) 80,443 to any tcpflags syn,ack in not diverted not sockarg recv em0
/opt/zapret/nfq/dvtws --port=989 --dpi-desync=split2
```

PF в FreeBSD:
Настройка аналогична OpenBSD, но есть важные нюансы.

1) В FreeBSD поддержка PF в `tpws` отключена по умолчанию. Чтобы ее включить, нужно использовать параметр `--enable-pf`.
2) Нельзя сделать IPv6 rdr на `::1`. Нужно делать на link-local адрес входящего интерфейса.
Смотрите через `ifconfig` адрес `fe80:...` и добавляете в правило.
3) Синтаксис `pf.conf` немного отличается. Более новая версия PF.
4) Лимит на количество элементов таблиц задается так: `sysctl net.pf.request_maxcount=2000000`
5) divert-to сломан. Он работает, но не работает механизм предотвращения зацикливаний.
Кто-то уже написал патч, но в 14-RELEASE проблема все еще есть.
Следовательно, на данный момент работа `dvtws` через `pf` невозможна.

`/etc/pf.conf`:

```
rdr pass on em1 inet6 proto tcp to port {80,443} -> fe80::31c:29ff:dee2:1c4d port 988
rdr pass on em1 inet  proto tcp to port {80,443} -> 127.0.0.1 port 988
```

```sh
/opt/zapret/tpws/tpws --port=988 --enable-pf --bind-addr=127.0.0.1 --bind-iface6=em1 --bind-linklocal=force
```

В PF непонятно как делать rdr-to с той же системы, где работает proxy. Вариант с route-to у меня не заработал.

# pfsense

pfsense основано на FreeBSD.
pfsense использует фаервол `pf`, а он имеет проблемы с divert.
К счастью, модули `ipfw` и `ipdivert` присутствуют в поставке последних версий pfsense.
Их можно подгрузить через `kldload`.
В некоторых более старых версиях pfsense требуется изменить порядок фаерволов через `sysctl`, сделав `ipfw` первым.
В более новых эти параметры `sysctl` отсутствуют, но система работает как надо и без них.
В некоторых случаях фаервол `pf` может ограничивать возможности `dvtws`, в частности в области фрагментации IP.
Присутствуют по умолчанию правила scrub для реассемблинга фрагментов.
Бинарники из `binaries/freebsd-x64` собраны под FreeBSD 11. Они должны работать и на последующих версиях FreeBSD,
включая pfsense. Можно пользоваться `install_bin.sh`.

Пример скрипта автозапуска лежит в `init.d/pfsense`. Его следует поместить в `/usr/local/etc/rc.d` и отредактировать
на предмет правил `ipfw` и запуска демонов. Есть встроенный редактор `edit` как более приемлемая альтернатива `vi`.
Поскольку `git` отсутствует, копировать файлы удобнее всего через `ssh`. `curl` присутствует по умолчанию.
Можно скопировать zip с файлами `zapret` и распаковать в `/opt`, как это делается на других системах.
Тогда `dvtws` нужно запускать как `/opt/zapret/nfq/dvtws`. Либо скопировать только `dvtws` в `/usr/local/sbin`.
Как вам больше нравится.
`ipset` скрипты работают, крон есть. Можно сделать автообновление листов.

Если вас напрягает бедность имеющегося репозитория, можно включить репозиторий от FreeBSD, который по умолчанию выключен.
Поменяйте `no` на `yes` в `/usr/local/etc/pkg/repos/FreeBSD.conf`
Можно установить весь привычный soft, включая `git`, чтобы напрямую скачивать zapret с GitHub.

`/usr/local/etc/rc.d/zapret.sh`  (`chmod 755`):

```sh
# !/bin/sh

kldload ipfw
kldload ipdivert

# for older pfsense versions. newer do not have these sysctls

sysctl net.inet.ip.pfil.outbound=ipfw,pf
sysctl net.inet.ip.pfil.inbound=ipfw,pf
sysctl net.inet6.ip6.pfil.outbound=ipfw,pf
sysctl net.inet6.ip6.pfil.inbound=ipfw,pf

ipfw delete 100
ipfw add 100 divert 989 tcp from any to any 80,443 out not diverted xmit em0
pkill ^dvtws$
dvtws --daemon --port 989 --dpi-desync=split2

# required for newer pfsense versions (2.6.0 tested) to return ipfw to functional state

pfctl -d ; pfctl -e
```

Что касается `tpws`, то видимо имеется некоторый конфликт двух фаерволов, и правила fwd в `ipfw` не работают.
Работает перенаправление средствами `pf` как описано в разделе по FreeBSD.
В `pf` можно изменять правила только целыми блоками - якорями (anchors). Нельзя просто так добавить или удалить что-то.
Но чтобы какой-то anchor был обработан, на него должна быть ссылка из основного набора правил.
Его трогать нельзя, иначе порушится весь фаервол.
Поэтому придется править код скриптов pfsense. Поправьте `/etc/inc/filter.inc` следующим образом:

```
 .................
 /*MOD*/
 $natrules .= "# ZAPRET redirection\n";
 $natrules .= "rdr-anchor \"zapret\"\n";

$natrules .= "# TFTP proxy\n";
 $natrules .= "rdr-anchor \"tftp-proxy/*\"\n";
 .................
```

Напишите файл с содержимым anchor-а (например, `/etc/zapret.anchor`):

```
rdr pass on em1 inet  proto tcp to port {80,443} -> 127.0.0.1 port 988
rdr pass on em1 inet6 proto tcp to port {80,443} -> fe80::20c:29ff:5ae3:4821 port 988
```

`fe80::20c:29ff:5ae3:4821` замените на ваш link local адрес LAN интерфейса, либо уберите строчку, если IPv6 не нужен.

Добавьте в автозапуск, `/usr/local/etc/rc.d/zapret.sh`:

```sh
pfctl -a zapret -f /etc/zapret.anchor
pkill ^tpws$
tpws --daemon --port=988 --enable-pf --bind-addr=127.0.0.1 --bind-iface6=em1 --bind-linklocal=force --split-http-req=method --split-pos=2
```

После перезагрузки проверьте, что правила создались:

```
[root@pfSense /]# pfctl -s nat
no nat proto carp all
nat-anchor "natearly/*" all
nat-anchor "natrules/*" all
...................
no rdr proto carp all
rdr-anchor "zapret" all
rdr-anchor "tftp-proxy/*" all
rdr-anchor "miniupnpd" all
[root@pfSense /]# pfctl -s nat -a zapret
rdr pass on em1 inet proto tcp from any to any port = http -> 127.0.0.1 port 988
rdr pass on em1 inet proto tcp from any to any port = https -> 127.0.0.1 port 988
rdr pass on em1 inet6 proto tcp from any to any port = http -> fe80::20c:29ff:5ae3:4821 port 988
rdr pass on em1 inet6 proto tcp from any to any port = https -> fe80::20c:29ff:5ae3:4821 port 988
```

Так же есть более элегантный способ запуска `tpws` через @reboot в `cron` и правило перенаправления в UI.
Это позволит не редактировать код pfsense.

# OpenBSD

В `tpws` бинд по умолчанию только на IPv6. для бинда на IPv4 указать `--bind-addr=0.0.0.0`.
Используйте `--bind-addr=0.0.0.0 --bind-addr=::` для достижения того же результата, как в других ОС по умолчанию.
(лучше все же так не делать, а сажать на определенные внутренние адреса или интерфейсы)

`tpws` для проходящего трафика:

`/etc/pf.conf`:

```
pass in quick on em1 inet  proto tcp to port {80,443} rdr-to 127.0.0.1 port 988
pass in quick on em1 inet6 proto tcp to port {80,443} rdr-to ::1 port 988
```

```sh
pfctl -f /etc/pf.conf
tpws --port=988 --user=daemon --bind-addr=::1 --bind-addr=127.0.0.1
```

В PF непонятно как делать rdr-to с той же системы, где работает proxy. Вариант с route-to у меня не заработал.
Поддержка rdr-to реализована через `/dev/pf`, поэтому прозрачный режим требует root.

`dvtws` для всего трафика:

`/etc/pf.conf`:

```
pass in  quick on em0 proto tcp from port {80,443} flags SA/SA divert-packet port 989 no state
pass in  quick on em0 proto tcp from port {80,443} no state
pass out quick on em0 proto tcp to   port {80,443} divert-packet port 989 no state
```

```sh
pfctl -f /etc/pf.conf
./dvtws --port=989 --dpi-desync=split2
```

`dvtws` для трафика только на таблицу `zapret`, за исключением таблицы `nozapret`:

`/etc/pf.conf`:

```
set limit table-entries 2000000
table <zapret> file "/opt/zapret/ipset/zapret-ip.txt"
table <zapret-user> file "/opt/zapret/ipset/zapret-ip-user.txt"
table <nozapret> file "/opt/zapret/ipset/zapret-ip-exclude.txt"
pass out quick on em0 inet  proto tcp to   <nozapret> port {80,443}
pass in  quick on em0 inet  proto tcp from <zapret>  port {80,443} flags SA/SA divert-packet port 989 no state
pass in  quick on em0 inet  proto tcp from <zapret>  port {80,443} no state
pass out quick on em0 inet  proto tcp to   <zapret>  port {80,443} divert-packet port 989 no state
pass in  quick on em0 inet  proto tcp from <zapret-user>  port {80,443} flags SA/SA divert-packet port 989 no state
pass in  quick on em0 inet  proto tcp from <zapret-user>  port {80,443} no state
pass out quick on em0 inet  proto tcp to   <zapret-user>  port {80,443} divert-packet port 989 no state
table <zapret6> file "/opt/zapret/ipset/zapret-ip6.txt"
table <zapret6-user> file "/opt/zapret/ipset/zapret-ip-user6.txt"
table <nozapret6> file "/opt/zapret/ipset/zapret-ip-exclude6.txt"
pass out quick on em0 inet6 proto tcp to   <nozapret6> port {80,443}
pass in  quick on em0 inet6 proto tcp from <zapret6> port {80,443} flags SA/SA divert-packet port 989 no state
pass in  quick on em0 inet6 proto tcp from <zapret6> port {80,443} no state
pass out quick on em0 inet6 proto tcp to   <zapret6> port {80,443} divert-packet port 989 no state
pass in  quick on em0 inet6 proto tcp from <zapret6-user>  port {80,443} flags SA/SA divert-packet port 989 no state
pass in  quick on em0 inet6 proto tcp from <zapret6-user>  port {80,443} no state
pass out quick on em0 inet6 proto tcp to   <zapret6-user> port {80,443} divert-packet port 989 no state
```

```sh
pfctl -f /etc/pf.conf
./dvtws --port=989 --dpi-desync=split2
```

divert-packet автоматически вносит обратное правило для перенаправления.
Трюк с no state и in правилом позволяет обойти эту проблему, чтобы напрасно не гнать массивный трафик через `dvtws`.

В OpenBSD `dvtws` все фейки отсылает через divert socket, поскольку эта возможность через raw sockets заблокирована.
Видимо, `pf` автоматически предотвращает повторный заворот diverted фреймов, поэтому проблемы зацикливания нет.

OpenBSD принудительно пересчитывает TCP checksum после divert, поэтому, скорее всего,
`--dpi-desync-fooling=badsum` у вас не заработает. При использовании этого параметра
`dvtws` предупредит о возможной проблеме.

Скрипты из `ipset` не перезагружают таблицы в PF по умолчанию.
Чтобы они это делали, добавьте параметр в `/opt/zapret/config`:

```sh
LISTS_RELOAD="pfctl -f /etc/pf.conf"
```

Более новые версии `pfctl` понимают команду перезагрузить только таблицы: `pfctl -Tl -f /etc/pf.conf`.
Но это не относится к OpenBSD 6.8. В новых FreeBSD есть.
Не забудьте выключить сжатие gzip:

```sh
GZIP_LISTS=0
```

Если в вашей конфигурации какого-то файла листа нет, то его необходимо исключить из правил PF.
Если вдруг листа нет, и он задан в `pf.conf`, будет ошибка перезагрузки фаервола.
После настройки обновление листов можно поместить в cron:

```sh
crontab -e
```

дописать строчку: `0 12 */2 * * /opt/zapret/ipset/get_config.sh`

# macOS

Изначально ядро этой ОС "darwin" основывалось на BSD, потому в ней много похожего на другие версии BSD.
Однако, как и в других массовых коммерческих проектах, приоритеты смещаются в сторону от оригинала.
Яблочники что хотят, то и творят.
Раньше был `ipfw`, потом его убрали, заменили на PF.
Есть сомнения, что divert сокеты в ядре остались. Попытка создать divert socket не выдает ошибок,
но полученный сокет ведет себя точно так же, как raw, со всеми его унаследованными косяками + еще яблочно специфическими.
В PF divert-packet не работает. Простой grep бинарника pfctl показывает, что там нет слова "divert",
а в других версиях BSD оно есть. `dvtws` собирается, но совершенно бесполезен.

`tpws` удалось адаптировать, он работоспособен. Получение адреса назначения для прозрачного прокси в PF (DIOCNATLOOK)
убрали из заголовков в новых SDK, сделав фактически недокументированным.
В `tpws` перенесены некоторые определения из более старых версий яблочных SDK. С ними удалось завести прозрачный режим.
Однако, что будет в следующих версиях угадать сложно. Гарантий нет.
Еще одной особенностью PF в macOS является проверка на рута в момент обращения к `/dev/pf`, чего нет в остальных BSD.
`tpws` по умолчанию сбрасывает рутовые привилегии. Необходимо явно указать параметр `--user=root`.
В остальном PF себя ведет похоже на FreeBSD. Синтаксис `pf.conf` тот же.

На macOS работает редирект как с проходящего трафика, так и с локальной системы через route-to.
Поскольку `tpws` вынужден работать под root, для исключения рекурсии приходится пускать исходящий от root трафик напрямую.
Отсюда имеем недостаток: обход DPI для рута работать не будет.

Если вы пользуетесь MaсOS в качестве IPv6 роутера, то нужно будет решить вопрос с регулярно изменяемым link-local адресом.
С некоторых версий macOS использует по умолчанию постоянные "secured" IPv6 адреса вместо генерируемых на базе MAC адреса.
Все замечательно, но есть одна проблема. Постоянными остаются только global scope адреса.
Link locals периодически меняются. Смена завязана на системное время. Перезагрузки адрес не меняют,
Но если перевести время на день вперед и перезагрузиться - link local станет другим. (по крайней мере в VMware это так)
Информации по вопросу крайне мало, но тянет на баг. Не должен меняться link local. Скрывать link local не имеет смысла,
а динамический link local нельзя использовать в качестве адреса шлюза.
Проще всего отказаться от "secured" адресов.
Поместите строчку `net.inet6.send.opmode=0` в `/etc/sysctl.conf`. Затем перезагрузите систему.
Все равно для исходящих соединений будут использоваться temporary адреса, как и в других системах.
Или вам идея не по вкусу, можно прописать дополнительный статический IPv6 из диапазона `fc00::/7` -
выберите любой с длиной префикса 128. Это можно сделать в системных настройках, создав дополнительный адаптер на базе
того же сетевого интерфейса, отключить в нем IPv4 и вписать статический IPv6. Он добавится к автоматически настраиваемым.

Настройка `tpws` на macOS в прозрачном режиме только для исходящих запросов:

`/etc/pf.conf`:

```
rdr pass on lo0 inet  proto tcp from !127.0.0.0/8 to any port {80,443} -> 127.0.0.1 port 988
rdr pass on lo0 inet6 proto tcp from !::1 to any port {80,443} -> fe80::1 port 988
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port {80,443} user { >root }
pass out route-to (lo0 fe80::1) inet6 proto tcp from any to any port {80,443} user { >root }
```

```sh
pfctl -ef /etc/pf.conf
/opt/zapret/tpws/tpws --user=root --port=988 --bind-addr=127.0.0.1 --bind-iface6=lo0 --bind-linklocal=force
```

Настройка `tpws` на macOS роутере в прозрачном режиме, где `en1` - LAN.

```
ifconfig en1 | grep fe80
        inet6 fe80::bbbb:bbbb:bbbb:bbbb%en1 prefixlen 64 scopeid 0x8
```

`/etc/pf.conf`:

```
rdr pass on en1 inet  proto tcp from any to any port {80,443} -> 127.0.0.1 port 988
rdr pass on en1 inet6 proto tcp from any to any port {80,443} -> fe80::bbbb:bbbb:bbbb:bbbb port 988
rdr pass on lo0 inet  proto tcp from !127.0.0.0/8 to any port {80,443} -> 127.0.0.1 port 988
rdr pass on lo0 inet6 proto tcp from !::1 to any port {80,443} -> fe80::1 port 988
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port {80,443} user { >root }
pass out route-to (lo0 fe80::1) inet6 proto tcp from any to any port {80,443} user { >root }
```

```sh
pfctl -ef /etc/pf.conf
/opt/zapret/tpws/tpws --user=root --port=988 --bind-addr=127.0.0.1 --bind-iface6=lo0 --bind-linklocal=force --bind-iface6=en1 --bind-linklocal=force
```

Сборка: `make -C /opt/zapret mac`

Скрипты получения листов `ipset/*.sh` работают.
Если будете пользоваться `ipset/get_combined.sh`, нужно установить gnu `grep` через brew.
Имеющийся очень старый и безумно медленный с опцией `-f`.

## Простая установка

В macOS поддерживается `install_easy.sh`

В комплекте идут бинарники, собранные под 64-bit с опцией `-mmacosx-version-min=10.8`.
Они должны работать на всех поддерживаемых версиях macOS.
Если вдруг не работают - можно собрать свои. Developer tools ставятся автоматом при запуске `make`.

**Internet sharing средствами системы НЕ ПОДДЕРЖИВАЕТСЯ**
Поддерживается только роутер, настроенный своими силами через PF.
Если вы вдруг включили шаринг, а потом выключили, то доступ к сайтам может пропасть совсем.
Лечение: `pfctl -f /etc/pf.conf`.
Если вам нужен шаринг интернета, лучше отказаться от прозрачного режима и использовать SOCKS.

Для автостарта используется `launchd` (`/Library/LaunchDaemons/zapret.plist`).
Управляющий скрипт: `/opt/zapret/init.d/macos/zapret`.
Следующие команды работают с `tpws` и фаерволом одновременно (если `INIT_APPLY_FW=1` в `config`):

```sh
/opt/zapret/init.d/macos/zapret start
/opt/zapret/init.d/macos/zapret stop
/opt/zapret/init.d/macos/zapret restart
```

Работа только с `tpws`:

```sh
/opt/zapret/init.d/macos/zapret start-daemons
/opt/zapret/init.d/macos/zapret stop-daemons
/opt/zapret/init.d/macos/zapret restart-daemons
```

Работа только с PF:

```sh
/opt/zapret/init.d/macos/zapret start-fw
/opt/zapret/init.d/macos/zapret stop-fw
/opt/zapret/init.d/macos/zapret restart-fw
```

Перезагрузка всех IP таблиц из файлов:

```sh
/opt/zapret/init.d/macos/zapret reload-fw-tables
```

Инсталлятор настраивает `LISTS_RELOAD` в `config`, так что скрипты `ipset/*.sh` автоматически перезагружают IP таблицы в PF.
Автоматически создается cron job на `ipset/get_config.sh`, по аналогии с OpenWrt.

При `start-fw` скрипт автоматически модифицирует `/etc/pf.conf`, вставляя туда anchors "zapret".
Модификация рассчитана на `pf.conf`, в котором сохранены дефолтные anchors от Apple.
Если у вас измененный `pf.conf` и модификация не удалась, об этом будет предупреждение. Не игнорируйте его.
В этом случае вам нужно вставить в свой `pf.conf` (в соответствии с порядком типов правил):

```
rdr-anchor "zapret"
anchor "zapret"
```

При деинсталляции через `uninstall_easy.sh` модификации `pf.conf` убираются.

`start-fw` создает 3 файла anchors в `/etc/pf.anchors`: `zapret`, `zapret-v4`, `zapret-v6`.
Последние 2 подключаются из anchor "zapret".
Таблицы `nozapret`, `nozapret6` принадлежат anchor "zapret".
Таблицы `zapret`, `zapret-user` - в anchor "zapret-v4".
Таблицы `zapret6`, `zapret6-user` - в anchor "zapret-v6".
Если какая-то версия протокола отключена - соответствующий anchor пустой и не упоминается в anchor "zapret".
Таблицы и правила создаются только на те листы, которые фактически есть в директории ipset.

## Вариант custom

Так же как и в других системах, поддерживаемых в простом инсталляторе, можно создавать свои custom скрипты.
Расположение: `/opt/zapret/init.d/macos/custom`

`zapret_custom_daemons()` получает в `$1` "0" или "1". "0" - stop, "1" - start
custom firewall отличается от Linux варианта.
Вместо заполнения `iptables` вам нужно сгенерировать правила для `zapret-v4` и`zapret-v6` anchors и выдать их в stdout.
Это делается в функциях `zapret_custom_firewall_v4()` и `zapret_custom_firewall_v6()`.
Определения таблиц заполняются основным скриптом - вам это делать не нужно.
Можно ссылаться на таблицы `zapret` и `zapret-user` в v4, `zapret6` и `zapret6-user`.

Cм. пример в файле `custom-tpws`.
