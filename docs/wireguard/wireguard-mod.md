# Важное замечание

Эта инструкция написана еще до включения WireGuard в ядро Linux.
Процесс сборки для in-tree модулей отличается.
Цель данного чтива - дать идею для программистов как можно исправить исходники WireGuard для преодоления DPI.
Автор не преследует цели поддерживать готовые патчи для актуальных версий.
Вместо патчинга гораздо проще использовать навесное решение ipobfs.

# Патчинг

Посвящено возможной блокировке в РФ VPN протоколов через DPI.
Предпосылками являются последние законодательные акты и во всю сочащиеся "секретные" записки.
В РФ разрабатываются и готовятся к применению более продвинутые решения по блокировке трафика.
Вполне вероятно, будут резать стандартные VPN протоколы. Нам надо быть к этому готовыми.

Один из возможных и перспективных путей решения данного вопроса - кастомная модификация исходников VPN с целью незначительного изменения протокола, ломающего стандартные модули обнаружения в DPI.
Это относительно сложно, доступно только для гиков.
Никто не будет разрабатывать специальные модули обнаружения в DPI, если только кто-то не сделает простое и удобное решение для всех, и его станут широко применять.
Но это маловероятно, и даже если и так, то всегда можно модифицировать протокол чуток по другому.
Делать моды для DPI несравненно дольше и дороже, чем клепать на коленке изменения протокола для WireGuard.

**ЗАМЕЧАНИЕ:** альтернативой модификации конечного софта для VPN является использование "навесных" обфускаторов, см. [одно из решений](https://github.com/bol-van/ipobfs).

Рассмотрю, что нам надо пропатчить в WireGuard.
Модифицированный WireGuard проверен на виртуалках с десктопным Linux, он работает, сообщения в wireshark действительно не вписываются в стандартный протокол и не опознаются.

WireGuard протокол очень простой. Все сообщения описаны в `messages.h`. Поставим себе целью сделать 2 простые модификации:

1) Добавим в начало всех сообщений немного мусора, чтобы изменить размер сообщений и смещения полей
2) Изменим коды типов сообщений

Этого может быть вполне достаточно для обмана DPI:

`messages.h`:

```h
/*
enum message_type {
 MESSAGE_INVALID = 0,
 MESSAGE_HANDSHAKE_INITIATION = 1,
 MESSAGE_HANDSHAKE_RESPONSE = 2,
 MESSAGE_HANDSHAKE_COOKIE = 3,
 MESSAGE_DATA = 4
};
*/

// MOD: message type
enum message_type {
 MESSAGE_INVALID = 0xE319CCD0,
 MESSAGE_HANDSHAKE_INITIATION = 0x48ADE198,
 MESSAGE_HANDSHAKE_RESPONSE = 0xFCA6A8F3,
 MESSAGE_HANDSHAKE_COOKIE = 0x64A3BB18,
 MESSAGE_DATA = 0x391820AA
};

// MOD: generate fast trash without true RNG
__le32 gen_trash(void);

struct message_header {
 /* The actual layout of this that we want is:
  * u8 type
  * u8 reserved_zero[3]
  *
  * But it turns out that by encoding this as little endian,
  * we achieve the same thing, and it makes checking faster.
  */

 // MOD: trash field to change message size and add 4 byte offset to all fields
 __le32 trash;

 __le32 type;
};
```

Напишем функцию для генерации `trash`. Функция должна быть быстрая, важно не замедлить скорость.
Мы не рассчитываем, что нас будут специально ловить, иначе бы пришлось делать полноценный обфускатор.
Задача лишь сломать стандартный модуль обнаружения протокола WireGuard. Потому истинная рандомность `trash` не важна.
Но все же немного "трэша" не повредит. Гонки между тредами так же пофигистичны. Это же трэш.

`noise.c`:

```c
// MOD: trash generator
__le32 gtrash = 0;
__le32 gen_trash(void)
{
 if (gtrash)
  gtrash = gtrash*1103515243 + 12345;
 else
  // first value is true random
  get_random_bytes_wait(&gtrash, sizeof(gtrash));
 return gtrash;
}
```

Теперь осталось найти все места, где создаются сообщения и внести туда заполнение поля `trash`.
Сообщений всего 4. Их можно найти по присваиванию полю type одного из значений enum message_type.

* 2 места в `noise.c` в функциях `wg_noise_handshake_create_initiation` и `wg_noise_handshake_create_response`,
* 1 место в `cookie.c` в функции `wg_cookie_message_create`.

Дописываем в конец инициализации структуры сообщения :

```c
// MOD: randomize trash
 dst->header.trash = gen_trash()
```

И в 1 место в `send.c` в функции `encrypt_packet`:

```c
// MOD: randomize trash
 header->header.trash = gen_trash()
```

Вот и весь патчинг. Полный patch (версия `wireguard 0.0.20190123`) лежит в `010-wg-mod.patch`.
Патчинг кода - самое простое. Для десктопного Linux дальше все просто.
Пересобираем через `make`, устанавливаем через `make install`, перегружаем модуль `wireguard`, перезапускаем интерфейсы, и все готово.

# Установка и запуск

Настоящий геморрой начнется, когда вы это попытаетесь засунуть на роутер под OpenWrt.
Одна из больших проблем Linux - отсутствие совместимости драйверов на уровне бинарников.
Поэтому собирать необходимо в точности под вашу версию ядра и в точности под его `.config`.
Вам придется либо полностью самостоятельно собирать всю прошивку, либо найти SDK в точности от вашей версии прошивки для вашей архитектуры и собрать модуль с помощью этого SDK.
Последний вариант более легкий. Для сборки вам понадобится система на Linux x86_64. Ее можно установить в виртуалке.
Теоретически можно пользоваться WSL из Windows 10, но на практике там очень медленное I/O, по крайней мере на старых версиях Windows 10. Безумно медленное. Будете собирать вечность.
Может в новых Windows 10 что-то и улучшили, но я бы сразу рассчитывал на полноценный Linux.

Находим [здесь](https://downloads.openwrt.org/) вашу версию. Скачиваем файл `openwrt-sdk-*.tar.xz` или `lede-sdk-*.tar.xz`.
Например: [https://downloads.openwrt.org/releases/18.06.2/targets/ar71xx/generic/openwrt-sdk-18.06.2-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64.tar.xz](https://downloads.openwrt.org/releases/18.06.2/targets/ar71xx/generic/openwrt-sdk-18.06.2-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64.tar.xz).
Если ваша версия непонятна или стара, то проще будет найти последнюю прошивку и перешить роутер.
Распаковываем SDK. Следующими командами можно собрать оригинальный вариант WireGuard:

```sh
scripts/feeds update -a
scripts/feeds install -a
make defconfig
make -j 4 package/wireguard/compile
```

Сборка будет довольно долгой. Ведь придется подтащить ядро, собрать его, собрать зависимости.
`-j 4` означает использовать 4 потока. Впишите вместо 4 количество доступных CPU cores.

Получим следующие файлы:

```
openwrt-sdk-18.06.2-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/bin/targets/ar71xx/generic/packages/kmod-wireguard_4.9.152+0.0.20190123-1_mips_24kc.ipk
openwrt-sdk-18.06.2-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/bin/packages/mips_24kc/base/wireguard-tools_0.0.20190123-1_mips_24kc.ipk
```

Но это будет оригинальный `wireguard`. Нам нужен патченный.
Установим `quilt` и `mc` для нормального редактора вместо `vim`:

```sh
sudo apt-get update
sudo apt-get install quilt mc
make package/wireguard/clean
make package/wireguard/prepare V=s QUILT=1
```

Сорцы приготовлены для сборки в:

```
openwrt-sdk-18.06.2-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/build_dir/target-mips_24kc_musl/linux-ar71xx_generic/WireGuard-0.0.20190123/src
```

```sh
cd build_dir/target-mips_24kc_musl/linux-ar71xx_generic/WireGuard-0.0.20190123/src
quilt push -a
quilt new 010-wg-mod.patch
export EDITOR=mcedit
```

Далее будет открываться редактор `mcedit`, в который нужно вносить изменения в каждый файл :

```sh
quilt edit messages.h
quilt edit cookie.c
quilt edit noise.c
quilt edit send.c
quilt diff
quilt refresh
```

Получили файл патча в:

```
openwrt-sdk-18.06.2-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/build_dir/target-mips_24kc_musl/linux-ar71xx_generic/WireGuard-0.0.20190123/patches/010-wg-mod.patch
```

Выходим в корень SDK и выполняем:

```sh
make package/wireguard/compile V=99
```

Если не было ошибок, то получили измененные ipk.
Патч можно зафиксировать в описании пакета:

```sh
make package/wireguard/update
```

Получим:

```
openwrt-sdk-18.06.2-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/feeds/base/package/network/services/wireguard/patches/010-wg-mod.patch
```

При последующей очистке и пересборке он будет автоматом применяться.

**АЛЬТЕРНАТИВА:** можно не возиться с quilt. Сделайте:

```sh
make package/wireguard/clean
make package/wireguard/prepare
```

и напрямую модифицируйте или копируйте файлы в:

```
openwrt-sdk-18.06.2-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/build_dir/target-mips_24kc_musl/linux-ar71xx_generic/WireGuard-0.0.20190123/src
```

затем:

```sh
make package/wireguard/compile
```

Если нужно поменять версию WireGuard, то идите в

```
openwrt-sdk-18.06.2-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/feeds/base/package/network/services/wireguard/Makefile
```

поменяйте там версию в `PKG_VERSION` на последнюю [отсюда](https://git.zx2c4.com/WireGuard), скачайте `tar.xz` с этой версией, вычислите его `sha256sum`, впишите в `PKG_HASH`.

1 раз где-нибудь пропатчите файлы последней версии WireGuard в текстовом редакторе, скопируйте в `build_dir`,
сделайте версию для OpenWrt. эти же файлы скопируйте на ваш сервер с десктопным Linux, сделайте там `make` / `make install`

Но имейте в виду, что `build_dir` - локация для временных файлов.
`make clean` оттуда все снесет, включая ваши модификации.
Модифицированные файлы лучше сохранить отдельно, чтобы потом было легко скопировать обратно.

Полученные `.ipk` копируем на роутер в `/tmp`, устанавливаем так:

```sh
cd /tmp
rm -r /tmp/opkg-lists
opkg install *.ipk
```

Если требует зависимостей, то:

```sh
opkg update
opkg install <зависимости>
rm -r /tmp/opkg-lists
opkg install *.ipk
```

В `/tmp/opkg-lists` `opkg` хранит кэш списка пакетов.
Если попытаться установить файл `.ipk`, и такой же пакет найдется в репозитории, opkg будет устанавливать из репозитория.
А нам это не надо.

```sh
rmmod wireguard
kmodloader
dmesg | tail
```

должны увидеть что-то вроде:

```
[8985.415490] wireguard: WireGuard 0.0.20190123 loaded. See <www.wireguard.com> for information.
[8985.424178] wireguard: Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
```

значит, модуль загрузился.

Могут понадобиться ключи `opkg` `--force-reinstall`, `--force-depends`.
`--force-depends` поможет при несоответствии hash версии ядра. То есть версия x.x.x та же самая, но hash конфигурации разный.
При несоответствии x.x.x вы что-то делаете не так, работать это не будет.
Например: `4.14.56-1-b1186491495127cc6ff81d29c00a91fc`, `4.14.56-1-3f8a21a63974cfb7ee67e41f2d4b805d`
Это свидетельствует о несоответствии `.config` ядра при сборке прошивки и в SDK.
Если несоответствие легкое, то может все прокатить, но при более серьезной разнице в `.config` модуль может не загрузиться или вызвать стабильные или хаотические падения ядра и перезагрузки (включая вариант бесконечной перезагрузки - bootloop).
Так что перед `--force-depends` убедитесь, что знаете как лечится такая ситуация, и не стоит это делать при отсутствии физического
доступа к девайсу.

Когда поднимите линк, и вдруг ничего не будет работать, то посмотрите в wireshark UDP пакеты на порт endpoint.
Они не должны начинаться с 0,1,2,3,4. В первых 4 байтах должен быть рандом, в следующих 4 байтах - значения из измененного enum message_type.
Если пакет все еще начинается с 0..4, значит, модуль `wireguard` оригинальный, что-то не собралось, не скомпилировалось, не перезапустилось.
В противном случае должен подняться линк, пинги ходить. Значит вы победили, поздравляю.
Регулятору будет намного сложнее поймать ваш VPN.
