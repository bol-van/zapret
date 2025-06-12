### tpws

Using `WSL` (Windows subsystem for Linux) it's possible to run `tpws` in socks mode under rather new builds of
windows 10 and windows server.
Its not required to install any linux distributions as suggested in most articles.
tpws is static binary. It doesn't need a distribution.

Install `WSL` : `dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all`

Copy `binaries/x86_64/tpws_wsl.tgz` to the target system.
Run : `wsl --import tpws "%USERPROFILE%\tpws" tpws_wsl.tgz`

Run tpws : `wsl -d tpws --exec /tpws --uid=1 --no-resolve --socks --bind-addr=127.0.0.1 --port=1080 <fooling_options>`

Configure socks as `127.0.0.1:1080` in a browser or another program.

Cleanup : `wsl --unregister tpws`

Tested in windows 10 build 19041 (20.04).

`--oob` , `--mss` and `--disorder` do not work.
RST detection in autohostlist scheme may not work.
WSL may glitch with splice. `--nosplice` may be required.


### winws

`winws` is `nfqws` version for windows. It's based on `windivert`. Most functions are working.
Large ip filters (ipsets) are not possible. Forwarded traffic and connection sharing are not supported.
Administrator rights are required.

Working with packet filter consists of two parts

1. In-kernel packet selection and passing selected packets to a packet filter in user mode.
In *nix it's done by `iptables`, `nftables`, `pf`, `ipfw`.
2. User mode packet filter processes packets and does DPI bypass magic.

Windows does not have part 1. No `iptables` exist. That's why 3rd party packet redirector is used.
It's called `windivert`. It works starting from `windows 7`. Kernel driver is signed but it may require to disable secure boot
or update windows 7. Read below for windows 7 windivert signing info.

Task of `iptables` is done inside `winws` through `windivert` filters. `Windivert` has it's own [filter language](https://reqrypt.org/windivert-doc.html#filter_language).
`winws` can automate filter construction using simple ip version and port filter. Raw filters are also supported.

```
 --wf-iface=<int>[:<int>]                       ; numeric network interface and subinterface indexes
 --wf-l3=ipv4|ipv6                              ; L3 protocol filter. multiple comma separated values allowed.
 --wf-tcp=[~]port1[-port2]                      ; TCP port filter. ~ means negation. multiple comma separated values allowed.
 --wf-udp=[~]port1[-port2]                      ; UDP port filter. ~ means negation. multiple comma separated values allowed.
 --wf-raw=<filter>|@<filename>                  ; raw windivert filter string or filename
 --wf-save=<filename>                           ; save windivert filter string to a file and exit
 --ssid-filter=ssid1[,ssid2,ssid3,...]          ; enable winws only if any of specified wifi SSIDs connected
 --nlm-filter=net1[,net2,net3,...]              ; enable winws only if any of specified NLM network is connected. names and GUIDs are accepted.
 --nlm-list[=all]                               ; list Network List Manager (NLM) networks. connected only or all.                           
```

`--wf-l3`, `--wf-tcp`, `--wf-udp` can take multiple comma separated arguments.

Interface indexes can be discovered using this command : `netsh int ip show int`

If you can't find index this way use `winws --debug` to see index there. Subinterface index is almost always 0 and you can omit it.

Multiple `winws` processes are allowed. However, it's discouraged to intersect their filters.

`--ssid-filter` allows to enable `winws` only if specified wifi networks are connected. `winws` auto detects SSID appearance and disappearance.
SSID names must be written in the same case as the system sees them. This option does not analyze routing and does not detect where traffic actually goes.
If multiple connections are available, the only thing that triggers `winws` operation is wifi connection presence. That's why it's a good idea to add also `--wf-iface` filter to not break ethernet, for example.

`--nlm-filter` is like `--ssid-filter` but works with names or GUIDs from Network List Manager. NLM names are those you see in Control Panel "Network and Sharing Center".
NLM networks are adapter independent. Usually MAC address of the default router is used to distinugish networks. NLM works with any type of adapters : ethernet, wifi, vpn and others.
That's why NLM is more universal than `ssid-filter`.

`Cygwin` shell does not run binaries if their directory has it's own copy of `cygwin1.dll`.
If you want to run `winws` from `cygwin` delete, rename or move `cygwin1.dll`.
`Cygwin` is required for `blockcheck.sh` support but `winws` itself can be run standalone without cygwin.

How to get `windows 7` and `winws` compatible `cygwin` :
```
curl -O https://www.cygwin.com/setup-x86_64.exe
setup-x86_64.exe --allow-unsupported-windows --no-verify --site http://ctm.crouchingtigerhiddenfruitbat.org/pub/cygwin/circa/64bit/2024/01/30/231215
```
You must choose to install `curl`. To compile from sources install `gcc-core`,`make`,`zlib-devel`.
Make from directory `nfq` using `make cygwin64` or `make cygwin32` for 64 and 32 bit versions.

`winws` requires `cygwin1.dll`, `windivert.dll`, `windivert64.sys` or `windivert32.sys`.
You can take them from `binaries/windows-x86_64` or `binaries/windows-x86`.

There's no `arm64` signed `windivert` driver and no `cygwin`.
But it's possible to use unsigned driver version in test mode and user mode components with x64 emulation.
x64 emulation requires `windows 11` and not supported in `windows 10`.

### windows 7 windivert signing

Requirements for windows driver signing have changed in 2021.
Official free updates of windows 7 ended in 2020.
After 2020 for the years paid updates were available (ESU).
One of the updates from ESU enables signatures used in windivert 2.2.2-A.
There are several options :

1. Take `windivert64.sys` and `windivert.dll` version `2.2.0-C` or `2.2.0-D` from [here](https://reqrypt.org/download).
Replace these 2 files in every location they are present.
In `zapret-win-bundle` they are in `zapret-winws` и `blockcheck/zapret/nfq` folders.
However this option still requires 10+ year old patch that enables SHA256 signatures.
If you're using win bundle you can simply run `win7\install_win7.cmd`

3. [Hack ESU](https://hackandpwn.com/windows-7-esu-patching)

4. Use `UpdatePack7R2` from simplix : https://blog.simplix.info
If you are in Russia or Belarus temporary change region in Control Panel.

### blockcheck

`blockcheck.sh` is written in posix shell and uses some standard posix utilites.
Windows does not have them. To execute `blockcheck.sh` use `cygwin` command prompt run as administrator.
It's not possible to use `WSL`. It's not the same as `cygwin`.
First run once `install_bin.sh` then `blockcheck.sh`.

Backslashes in windows paths shoud be doubled. Or use cygwin path notation.
```
cd "C:\\Users\\vasya"
cd "C:/Users/vasya"
cd "/cygdrive/c/Users/vasya"
```
`Cygwin` shell does not run binaries if their directory has it's own copy of `cygwin1.dll`.
If you want to run `winws` from `cygwin` delete, rename or move `cygwin1.dll`.

`Cygwin` is required only for `blockcheck.sh`. Standalone `winws` can be run without it.

To simplify things it's advised to use `zapret-win-bundle`.

### zapret-win-bundle

To make your life easier there's ready to use [bundle](https://github.com/bol-van/zapret-win-bundle) with `cygwin`,`blockcheck` and `winws`.

* `/zapret-winws` - standalone version of `winws` for everyday use. does not require any other folders.
* `/zapret-winws/_CMD_ADMIN.cmd` - open `cmd` as administrator in the current folder
* `/blockcheck/blockcheck.cmd` - run `blockcheck` with logging to `blockcheck/blockcheck.log`
* `/cygwin/cygwin.cmd` - run `cygwin` shell as current user
* `/cygwin/cygwin-admin.cmd` - run `cygwin` shell as administrator

There're aliases in cygwin shell for `winws`,`blockcheck`,`ip2net`,`mdig`. No need to mess with paths.
It's possible to send signals to `winws` using standard unix utilites : `pidof,kill,killall,pgrep,pkill`.
`Cygwin` shares common process list per `cygwin1.dll` copy. If you run a `winws` from `zapret-winws`
you won't be able to `kill` it because this folder contain its own copy of `cygwin1.dll`.

It's possible to use `cygwin` shell to make `winws` debug log. Use `tee` command like this :

```
winws --debug --wf-tcp=80,443 | tee winws.log
unix2dos winws.log
```

`winws.log` will be in `cygwin/home/<username>`. `unix2dos` helps with `windows 7` notepad. It's not necessary in `Windows 10` and later.

Because 32-bit systems are rare nowadays `zapret-win-bundle` exists only for `Windows x64/arm64`.

### auto start

To start `winws` with windows use windows task scheduler. There are `task_*.cmd` batch files in `binaries/windows-x86-64/zapret-winws`.
They create, remove, start and stop scheduled task `winws1`. They must be run as administrator.

Edit `task_create.cmd` and write your `winws` parameters to `%WINWS1%` variable. If you need multiple `winws` instances
clone the code in all cmd files to support multiple tasks `winws1,winws2,winws3,...`.

Tasks can also be controlled from GUI `taskschd.msc`.

Also you can use windows services the same way with `service_*.cmd`.
