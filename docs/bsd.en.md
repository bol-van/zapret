## Table of contents

- [Table of contents](#table-of-contents)
- [Supported versions](#supported-versions)
- [BSD features](#bsd-features)
- [FreeBSD](#freebsd)
  - [`dvtws` quick start](#dvtws-quick-start)
  - [PF in FreeBSD](#pf-in-freebsd)
  - [`pfsense`](#pfsense)
- [OpenBSD](#openbsd)
- [MacOS](#macos)
  - [MacOS easy install](#macos-easy-install)

## Supported versions

FreeBSD 11.x+ , OpenBSD 6.x+, partially MacOS Sierra+

Older versions may work or not.

## BSD features

BSD does not have NFQUEUE. Similar mechanism - divert sockets. In BSD compiling
the source from nfq directory result in `dvtws` binary instead of `nfqws`.
`dvtws` shares most of the code with `nfqws` and offers almost identical
parameters.

FreeBSD has 3 firewalls: IPFilter, ipfw and Packet Filter (PF). OpenBSD has
only PF.

To compile sources:

- FreeBSD: `make`
- OpenBSD: `make bsd`
- MacOS: `make mac`

Compile all programs:
```
make -C /opt/zapret
```

Divert sockets are internal type sockets in the BSD kernel. They have no
relation to network addresses or network packet exchange. They are identified
by a port number `1..65535`. Its like queue number in NFQUEUE. Traffic can be
diverted to a divert socket using firewall rule. If nobody listens on the
specified divert port packets are dropped. Its similar to NFQUEUE without
`--queue-bypass`.

`ipset/*.sh` scripts work with ipfw lookup tables if ipfw is present.

ipfw table is analog to linux `ipset`. Unlike ipsets ipfw tables share v4 an v6
addresses and subnets.

- If ipfw is absent scripts check LISTS_RELOAD config variable.
- If its present then scripts execute a command from LISTS_RELOAD.
- If LISTS_RELOAD=- scripts do not load tables even if ipfw exists.

PF can load ip tables from a file. To use this feature with `ipset/*.sh` scripts disable gzip file creation
using `GZIP_LISTS=0` directive in the `/opt/zapret/config` file.

BSD kernel doesn't implement splice syscall. tpws uses regular recv/send
operations with data copying to user space. Its slower but not critical.

`tpws` uses nonblocking sockets with linux specific epoll feature. In BSD systems
epoll is emulated by epoll-shim library on top of kqueue.

`dvtws` uses some programming HACKs, assumptions and knowledge of discovered
bugs and limitations. BSD systems have many limitations, version specific
features and bugs in low level networking, especially for ipv6. Many years have
passed but BSD code still has 15-20 year artificial limiters in the code. `dvtws`
uses additinal divert socket(s) for layer 3 packet injection if raw sockets do
not allow it. It works for the moment but who knows. Such a usage is not very
documented.

`mdig` and `ip2net` are fully compatible with BSD.


## FreeBSD

Divert sockets require special kernel module `ipdivert`.
Write the following to config files:

`/boot/loader.conf` (create if absent):
```
ipdivert_load="YES"
net.inet.ip.fw.default_to_accept=1
```

`/etc/rc.conf`:
```
firewall_enable="YES"
firewall_script="/etc/rc.firewall.my"
```

`/etc/rc.firewall.my`:
```
ipfw -q -f flush
```

Later you will add ipfw commands to `/etc/rc.firewall.my` to be reapplied after reboot.
You can also run zapret daemons from there. Start them with `--daemon` options, for example
```
pkill ^dvtws$
/opt/zapret/nfq/dvtws --port=989 --daemon --dpi-desync=multisplit --dpi-desync-split-pos=2
```

To restart firewall and daemons run : `/etc/rc.d/ipfw restart`

Assume `LAN="em1"`, `WAN="em0"`.

`tpws` transparent mode quick start.

For all traffic:
```
ipfw delete 100
ipfw add 100 fwd 127.0.0.1,988 tcp from me to any 80,443 proto ip4 xmit em0 not uid daemon
ipfw add 100 fwd ::1,988 tcp from me to any 80,443 proto ip6 xmit em0 not uid daemon
ipfw add 100 fwd 127.0.0.1,988 tcp from any to any 80,443 proto ip4 recv em1
ipfw add 100 fwd ::1,988 tcp from any to any 80,443 proto ip6 recv em1
/opt/zapret/tpws/tpws --port=988 --user=daemon --bind-addr=::1 --bind-addr=127.0.0.1
```

Process only table zapret with the exception of table nozapret:
```
ipfw delete 100
ipfw add 100 allow tcp from me to table\(nozapret\) 80,443
ipfw add 100 fwd 127.0.0.1,988 tcp from me to table\(zapret\) 80,443 proto ip4 xmit em0 not uid daemon
ipfw add 100 fwd ::1,988 tcp from me to table\(zapret\) 80,443 proto ip6 xmit em0 not uid daemon
ipfw add 100 allow tcp from any to table\(nozapret\) 80,443 recv em1
ipfw add 100 fwd 127.0.0.1,988 tcp from any to any 80,443 proto ip4 recv em1
ipfw add 100 fwd ::1,988 tcp from any to any 80,443 proto ip6 recv em1
/opt/zapret/tpws/tpws --port=988 --user=daemon --bind-addr=::1 --bind-addr=127.0.0.1
```

Tables zapret, nozapret, ipban are created by `ipset/*.sh` scripts the same way as in Linux.
Its a good idea to update tables periodically:
```
 crontab -e
```

Write the line:
```
0 12 */2 * * /opt/zapret/ipset/get_config.sh
```

When using `ipfw`, `tpws` does not require special permissions for transparent
mode. However without root its not possible to bind to ports less than 1024 and
change UID/GID. Without changing UID tpws will run into recursive loop, and
that's why its necessary to write ipfw rules with the right UID. Redirecting to
ports greater than or equal to 1024 is dangerous. If tpws is not running any
unprivileged process can listen to that port and intercept traffic.

### `dvtws` quick start

For all traffic:
```
ipfw delete 100
ipfw add 100 divert 989 tcp from any to any 80,443 out not diverted not sockarg xmit em0
# required for autottl mode only
ipfw add 100 divert 989 tcp from any 80,443 to any tcpflags syn,ack in not diverted not sockarg recv em0
/opt/zapret/nfq/dvtws --port=989 --dpi-desync=multisplit --dpi-desync-split-pos=2
```

Process only table zapret with the exception of table nozapret:
```
ipfw delete 100
ipfw add 100 allow tcp from me to table\(nozapret\) 80,443
ipfw add 100 divert 989 tcp from any to table\(zapret\) 80,443 out not diverted not sockarg xmit em0
# required for autottl mode only
ipfw add 100 divert 989 tcp from table\(zapret\) 80,443 to any tcpflags syn,ack in not diverted not sockarg recv em0
/opt/zapret/nfq/dvtws --port=989 --dpi-desync=multisplit --dpi-desync-split-pos=2
```

Reinjection loop avoidance. FreeBSD artificially ignores sockarg for ipv6 in
the kernel. This limitation is coming from the ipv6 early age. Code is still in
"testing" state. 10-20 years. Everybody forgot about it. `dvtws` sends ipv6
forged frames using another divert socket (HACK). they can be filtered out
using 'diverted'. ipv4 frames are filtered using 'sockarg'.

### PF in FreeBSD

The setup is similar to OpenBSD, but there are important nuances.
1. PF support is disabled by default in FreeBSD. Use parameter `--enable-pf`.
2. It's not possible to redirect to `::1`. Need to redirect to the link-local
   address of the incoming interface. Look for fe80:... address in ifconfig and
   use it for redirection target.
3. pf.conf syntax is a bit different from OpenBSD.
4. How to set maximum table size : sysctl net.pf.request_maxcount=2000000
5. `divert-to` is broken. Loop avoidance scheme does not work.
   This makes `dvtws` unusable with pf.
   Someone posted kernel patch but 14-RELEASE is still broken.

`/etc/pf.conf`:
```
rdr pass on em1 inet6 proto tcp to port {80,443} -> fe80::31c:29ff:dee2:1c4d port 988
rdr pass on em1 inet  proto tcp to port {80,443} -> 127.0.0.1 port 988
```

Then:
```
/opt/zapret/tpws/tpws --port=988 --enable-pf --bind-addr=127.0.0.1 --bind-iface6=em1 --bind-linklocal=force
```

Its not clear how to do rdr-to outgoing traffic. I could not make route-to
scheme work.


### `pfsense`

`pfsense` is based on FreeBSD. Binaries from `binaries/freebsd-x64` are
compiled in FreeBSD 11 and should work. Use `install_bin.sh`. pfsense uses pf
firewall which does not support divert. Fortunately ipfw and ipdivert modules
are present and can be kldload-ed. In older versions it's also necessary to
change firewall order using sysctl commands. In newer versions those sysctl
parameters are absent but the system behaves as required without them.
Sometimes pf may limit `dvtws` abilities. It scrubs ip fragments disabling `dvtws`
ipfrag2 desync mode.

There's autostart script example in `init.d/pfsense`. It should be placed to
`/usr/local/etc/rc.d` and edited. Write your ipfw rules and daemon start
commands.
curl is present by default. You can use it to download `tar.gz` release directly from github.
Or you can copy files using sftp.

Copy zip with zapret files to `/opt` and unpack there as it's done in other
systems. In this case run `dvtws` as `/opt/zapret/nfq/dvtws`. Or just copy
`dvtws` to `/usr/local/sbin`. As you wish. `ipset` scripts are working, cron is
present. It's possible to renew lists.

If you dont like poverty of default repos its possible to enable FreeBSD repo.
Change `no` to `yes` in `/usr/local/etc/pkg/repos/FreeBSD.conf` and `/usr/local/etc/pkg/repos/pfSense.conf`.

`/usr/local/etc/rc.d/zapret.sh` (chmod 755)
```
#!/bin/sh

kldload ipfw
kldload ipdivert

# for older pfsense versions. newer do not have these sysctls
sysctl net.inet.ip.pfil.outbound=ipfw,pf
sysctl net.inet.ip.pfil.inbound=ipfw,pf
sysctl net.inet6.ip6.pfil.outbound=ipfw,pf
sysctl net.inet6.ip6.pfil.inbound=ipfw,pf

ipfw delete 100
ipfw add 100 divert 989 tcp from any to any 80,443 out not diverted not sockarg xmit em0
pkill ^dvtws$
dvtws --daemon --port 989 --dpi-desync=multisplit --dpi-desync-split-pos=2

# required for newer pfsense versions (2.6.0 tested) to return ipfw to functional state
pfctl -d ; pfctl -e
```

I could not make tpws work from ipfw. Looks like there's some conflict between
two firewalls. Only PF redirection works. PF does not allow to freely add and
delete rules. Only anchors can be reloaded. To make an anchor work it must be
referred from the main ruleset. But its managed by pfsense scripts.

One possible solution would be to modify `/etc/inc/filter.inc` as follows:
```
    .................
    /* MOD */
    $natrules .= "# ZAPRET redirection\n";
    $natrules .= "rdr-anchor \"zapret\"\n";

    $natrules .= "# TFTP proxy\n";
    $natrules .= "rdr-anchor \"tftp-proxy/*\"\n";
    .................
```

Write the anchor code to `/etc/zapret.anchor`:
```
rdr pass on em1 inet  proto tcp to port {80,443} -> 127.0.0.1 port 988
rdr pass on em1 inet6 proto tcp to port {80,443} -> fe80::20c:29ff:5ae3:4821 port 988
```
Replace `fe80::20c:29ff:5ae3:4821` with your link local address of the LAN
interface or remove the line if ipv6 is not needed.

Autostart `/usr/local/etc/rc.d/zapret.sh`:
```
pfctl -a zapret -f /etc/zapret.anchor
pkill ^tpws$
tpws --daemon --port=988 --enable-pf --bind-addr=127.0.0.1 --bind-iface6=em1 --bind-linklocal=force --split-pos=2
```

After reboot check that anchor is created and referred from the main ruleset:
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

Also there's a way to add redirect in the pfsense UI and start `tpws` from cron using `@reboot` prefix.
This way avoids modification of pfsense code.

## OpenBSD

In OpenBSD default `tpws` bind is ipv6 only. To bind to ipv4 specify
`--bind-addr=0.0.0.0`.

Use `--bind-addr=0.0.0.0 --bind-addr=::` to achieve the same default bind as in
others OSes.

`tpws` for forwarded traffic only (OLDER OS versions):

`/etc/pf.conf`:
```
pass in quick on em1 inet  proto tcp to port {80,443} rdr-to 127.0.0.1 port 988
pass in quick on em1 inet6 proto tcp to port {80,443} rdr-to ::1 port 988
```

Then:
```
pfctl -f /etc/pf.conf
tpws --port=988 --user=daemon --bind-addr=::1 --bind-addr=127.0.0.1 --enable-pf
```

Its not clear how to do rdr-to outgoing traffic. I could not make route-to
scheme work. rdr-to support is done using /dev/pf, that's why transparent mode
requires root.

`tpws` for forwarded traffic only (NEWER OS versions):

```
pass on em1 inet proto tcp to port {80,443} divert-to 127.0.0.1 port 989
pass on em1 inet6 proto tcp to port {80,443} divert-to ::1 port 989
```

Then:
```
pfctl -f /etc/pf.conf
tpws --port=988 --user=daemon --bind-addr=::1 --bind-addr=127.0.0.1
```

tpws must be bound exactly to diverted IPs, not `0.0.0.0` or `::`.

It's also not clear how to divert connections from local system.


`dvtws` for all traffic:

`/etc/pf.conf`:
```
pass in  quick on em0 proto tcp from port {80,443} flags SA/SA divert-packet port 989 no state
pass in  quick on em0 proto tcp from port {80,443} no state
pass out quick on em0 proto tcp to   port {80,443} divert-packet port 989
```

Then:
```
pfctl -f /etc/pf.conf
./dvtws --port=989 --dpi-desync=multisplit --dpi-desync-split-pos=2
```

`dwtws` only for table zapret with the exception of table nozapret :

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

Then:
```
pfctl -f /etc/pf.conf
./dvtws --port=989 --dpi-desync=multisplit --dpi-desync-split-pos=2
```

divert-packet automatically adds the reverse rule. By default also incoming
traffic will be passwed to `dvtws`. This is highly undesired because it is waste
of cpu resources and speed limiter. The trick with "no state" and "in" rules
allows to bypass auto reverse rule.

`dvtws` in OpenBSD sends all fakes through a divert socket because raw sockets
have critical artificial limitations. Looks like pf automatically prevent
reinsertion of diverted frames. Loop problem does not exist.

OpenBSD forcibly recomputes tcp checksum after divert. Thats why most likely
dpi-desync-fooling=badsum will not work. `dvtws` will warn if you specify this
parameter.

`ipset` scripts do not reload PF by default. To enable reload specify command in
`/opt/zapret/config`:
```
LISTS_RELOAD="pfctl -f /etc/pf.conf"
```

Newer `pfctl` versions can reload tables only:
```
pfctl -Tl -f /etc/pf.conf
```

But OpenBSD 6.8 `pfctl` is old enough and does not support that. Newer FreeBSD do.

Don't forget to disable gzip compression:
```
GZIP_LISTS=0
```

If some list files do not exist and have references in pf.conf it leads to
error. You need to exclude those tables from pf.conf and referencing them
rules. After configuration is done you can put `ipset` script:
```
 crontab -e
```

Then write the line:
```
0 12 */2 * * /opt/zapret/ipset/get_config.sh
```

## MacOS

Initially, the kernel of this OS was based on BSD. That's why it is still BSD
but a lot was modified by Apple. As usual a mass commercial project priorities
differ from their free counterparts. Apple guys do what they want.

MacOS used to have ipfw but it was removed later and replaced by PF. It looks
like divert sockets are internally replaced with raw. Its possible to request a
divert socket but it behaves exactly as raw socket with all its BSD inherited +
apple specific bugs and feature. The fact is that divert-packet in
`/etc/pf.conf` does not work. pfctl binary does not contain the word `divert`.

`dvtws` does compile but is useless.

After some efforts `tpws` works. Apple has removed some important stuff from
their newer SDKs (DIOCNATLOOK) making them undocumented and unsupported.

With important definitions copied from an older SDK it was possible to make
transparent mode working again. But this is not guaranteed to work in the
future versions.

Another MacOS unique feature is root requirement while polling `/dev/pf`.

By default tpws drops root. Its necessary to specify `--user=root` to stay with
root.

In other aspects PF behaves very similar to FreeBSD and shares the same pf.conf
syntax.

In MacOS redirection works both for passthrough and outgoing traffic. Outgoing
redirection requires route-to rule. Because tpws is forced to run as root to
avoid loop its necessary to exempt root from the redirection. That's why DPI
bypass will not work for local requests from root.

If you do ipv6 routing you have to get rid of "secured" ipv6 address
assignment.

"secured" addresses are designed to be permanent and not related to the MAC
address.

And they really are. Except for link-locals.

If you just reboot the system link-locals will not change. But next day they
will change.

Not necessary to wait so long. Just change the system time to tomorrow and reboot.
Link-locals will change (at least they change in vmware guest). Looks like its a kernel bug.
Link locals should not change. Its useless and can be harmful. Cant use LL as a gateway.

The easiest solution is to disable "secured" addresses.

Outgoing connections prefer randomly generated temporary addressesas like in other systems.

Put the string `net.inet6.send.opmode=0` to `/etc/sysctl.conf`.  If not present
- create it.

Then reboot the system.

If you dont like this solution you can assign an additional static ipv6 address
from `fc00::/7` range with `/128` prefix to your LAN interface and use it as
the gateway address.

`tpws` transparent mode only for outgoing connections.

`/etc/pf.conf`:
```
rdr pass on lo0 inet  proto tcp from !127.0.0.0/8 to any port {80,443} -> 127.0.0.1 port 988
rdr pass on lo0 inet6 proto tcp from !::1 to any port {80,443} -> fe80::1 port 988
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port {80,443} user { >root }
pass out route-to (lo0 fe80::1) inet6 proto tcp from any to any port {80,443} user { >root }
```

Then:
```
pfctl -ef /etc/pf.conf
/opt/zapret/tpws/tpws --user=root --port=988 --bind-addr=127.0.0.1 --bind-iface6=lo0 --bind-linklocal=force
```

`tpws` transparent mode for both passthrough and outgoing connections. en1 - LAN.

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

Then:
```
pfctl -ef /etc/pf.conf
/opt/zapret/tpws/tpws --user=root --port=988 --bind-addr=127.0.0.1 --bind-iface6=lo0 --bind-linklocal=force --bind-iface6=en1 --bind-linklocal=force
```

Build from source : `make -C /opt/zapret mac`

`ipset/*.sh` scripts work.


### MacOS easy install

`install_easy.sh` supports MacOS

Shipped precompiled binaries are built for 64-bit MacOS with
`-mmacosx-version-min=10.8` option. They should run on all supported MacOS
versions. If no - its easy to build your own. Running `make` automatically
installs developer tools.

**WARNING**:
**Internet sharing is not supported!**

Routing is supported but only manually configured through PF. If you enable
internet sharing tpws stops functioning. When you disable internet sharing you
may lose web site access.

To fix:
```
pfctl -f /etc/pf.conf
```

If you need internet sharing use `tpws` socks mode.

`launchd` is used for autostart (`/Library/LaunchDaemons/zapret.plist`)

Control script: `/opt/zapret/init.d/macos/zapret`

The following commands fork with both tpws and firewall (if `INIT_APPLY_FW=1` in config)
```
/opt/zapret/init.d/macos/zapret start
/opt/zapret/init.d/macos/zapret stop
/opt/zapret/init.d/macos/zapret restart
```

Work with `tpws` only:
```
/opt/zapret/init.d/macos/zapret start-daemons
/opt/zapret/init.d/macos/zapret stop-daemons
/opt/zapret/init.d/macos/zapret restart-daemons
```

Work with PF only:
```
/opt/zapret/init.d/macos/zapret start-fw
/opt/zapret/init.d/macos/zapret stop-fw
/opt/zapret/init.d/macos/zapret restart-fw
```

Reloading PF tables:
```
/opt/zapret/init.d/macos/zapret reload-fw-tables
```

Installer configures `LISTS_RELOAD` in the config so `ipset *.sh` scripts
automatically reload PF tables. Installer creates cron job for `ipset
/get_config.sh`, as in OpenWRT.

start-fw script automatically patches `/etc/pf.conf` inserting there `zapret`
anchors. Auto patching requires pf.conf with apple anchors preserved. If your
`pf.conf` is highly customized and patching fails you will see the warning. Do
not ignore it.

In that case you need to manually insert "zapret" anchors to your `pf.conf`
(keeping the right rule type ordering):
```
rdr-anchor "zapret"
anchor "zapret"
unistall_easy.sh unpatches pf.conf
```
start-fw creates 3 anchor files in `/etc/pf.anchors` :
zapret,zapret-v4,zapret-v6.

- Last 2 are referenced by anchor `zapret`.
- Tables `nozapret`,`nozapret6` belong to anchor `zapret`.
- Tables `zapret`,`zapret-user` belong to anchor `zapret-v4`.
- Tables `zapret6`,`apret6-user` belong to anchor `zapret-v6`.

If an ip version is disabled then corresponding anchor is empty and is not
referenced from the anchor `zapret`. Tables are only created for existing list
files in the `ipset` directory.
