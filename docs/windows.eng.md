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
or update windows 7.

Task of `iptables` is done inside `winws` through `windivert` filters. `Windivert` has it's own [filter language](https://reqrypt.org/windivert-doc.html#filter_language).
`winws` can automate filter construction using simple ip version and port filter. Raw filters are also supported.

```
 --wf-iface=<int>[:<int>]                       ; numeric network interface and subinterface indexes
 --wf-l3=ipv4|ipv6                              ; L3 protocol filter. multiple comma separated values allowed.
 --wf-tcp=[~]port1[-port2]                      ; TCP port filter. ~ means negation. multiple comma separated values allowed.
 --wf-udp=[~]port1[-port2]                      ; UDP port filter. ~ means negation. multiple comma separated values allowed.
 --wf-raw=<filter>|@<filename>                  ; raw windivert filter string or filename
 --wf-save=<filename>                           ; save windivert filter string to a file and exit
```

`--wf-l3`, `--wf-tcp`, `--wf-udp` can take multiple comma separated arguments.

Interface indexes can be discovered using this command : `netsh int ip show int`

If you can't find index this way use `winws --debug` to see index there. Subinterface index is almost always 0 and you can omit it.

Multiple `winws` processes are allowed. However, it's discouraged to intersect their filters.

`Cygwin` shell does not run binaries if their directory has it's own copy of `cygwin1.dll`.
That's why exists separate standalone version in `binaries/win64/zapret-tpws`.
`Cygwin` is required for `blockcheck.sh` support but `winws` itself can be run standalone without cygwin.

How to get `windows 7` and `winws` compatible `cygwin` :
```
curl -O https://www.cygwin.com/setup-x86_64.exe
setup-x86_64.exe --allow-unsupported-windows --no-verify --site http://ctm.crouchingtigerhiddenfruitbat.org/pub/cygwin/circa/64bit/2024/01/30/231215
```
You must choose to install `curl`. To compile from sources install `gcc-core`,`make`,`zlib-devel`.

`winws` requires `cygwin1.dll`, `windivert.dll`, `windivert64.sys`. You can take them from `binaries/win64/zapret-winws`.

It's possible to build x86 32-bit version but this version is not shipped. You have to build it yourself.
32-bit `windivert` can be downloaded from it's developer github. Required version is 2.2.2.
There's no `arm64` signed `windivert` driver. You can compile it yourself but it will run only with disabled driver signature checks.


### blockcheck

`blockcheck.sh` is written in posix shell and uses some standard posix utilites.
Windows does not have them. To execute `blockcheck.sh` use `cygwin` command prompt run as administrator.
It's not possible to use `WSL`. It's not the same as `cygwin`.
First run once `install_bin.sh` then `blockcheck.sh`.

Backslashes in windows paths shoud be doubled. Or use cygwin path notation.
```
cd "C:\\Users\\vasya"
cd "/cygdrive/c/Users/vasya"
```
`Cygwin` is required only for `blockcheck.sh`. Standalone `winws` can be run without it.


### auto start

To start `winws` with windows use windows task scheduler. There are `task_*.cmd` batch files in `binaries/win64/zapret-winws`.
They create, remove, start and stop scheduled task `winws1`. They must be run as administrator.

Edit `task_create.cmd` and write your `winws` parameters to `%WINWS1%` variable. If you need multiple `winws` instances
clone the code in all cmd files to support multiple tasks `winws1,winws2,winws3,...`.

Tasks can also be controlled from GUI `taskschd.msc`.
