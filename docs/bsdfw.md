`WAN=em0`, `LAN=em1`

FreeBSD IPFW:

```sh
ipfw delete 100
ipfw add 100 fwd 127.0.0.1,988 tcp from me to any 80,443 proto ip4 xmit em0 not uid daemon
ipfw add 100 fwd ::1,988 tcp from me to any 80,443 proto ip6 xmit em0 not uid daemon
ipfw add 100 fwd 127.0.0.1,988 tcp from any to any 80,443 proto ip4 recv em1
ipfw add 100 fwd ::1,988 tcp from any to any 80,443 proto ip6 recv em1

ipfw delete 100
ipfw add 100 allow tcp from me to table\(nozapret\) 80,443
ipfw add 100 fwd 127.0.0.1,988 tcp from me to table\(zapret\) 80,443 proto ip4 xmit em0 not uid daemon
ipfw add 100 fwd ::1,988 tcp from me to table\(zapret\) 80,443 proto ip6 xmit em0 not uid daemon
ipfw add 100 allow tcp from any to table\(nozapret\) 80,443 recv em1
ipfw add 100 fwd 127.0.0.1,988 tcp from any to any 80,443 proto ip4 recv em1
ipfw add 100 fwd ::1,988 tcp from any to any 80,443 proto ip6 recv em1

/opt/zapret/tpws/tpws --port=988 --user=daemon --bind-addr=::1 --bind-addr=127.0.0.1

ipfw delete 100
ipfw add 100 divert 989 tcp from any to any 80,443 out not diverted xmit em0
# required for autottl mode
ipfw add 100 divert 989 tcp from any 80,443 to any tcpflags syn,ack in not diverted recv em0
# udp
ipfw add 100 divert 989 udp from any to any 443 out not diverted xmit em0

ipfw delete 100
ipfw add 100 allow tcp from me to table\(nozapret\) 80,443
ipfw add 100 divert 989 tcp from any to table\(zapret\) 80,443 out not diverted xmit em0

/opt/zapret/nfq/dvtws --port=989 --debug --dpi-desync=split
```

sample `ipfw` NAT setup:

```sh
WAN=em0
LAN=em1
ipfw -q flush
ipfw -q nat 1 config if $WAN unreg_only reset
ipfw -q add 10 allow ip from any to any via $LAN
ipfw -q add 20 allow ip from any to any via lo0
ipfw -q add 300 nat 1 ip4 from any to any in recv $WAN
ipfw -q add 301 check-state
ipfw -q add 350 skipto 390 tcp from any to any out xmit $WAN setup keep-state
ipfw -q add 350 skipto 390 udp from any to any out xmit $WAN keep-state
ipfw -q add 360 allow all from any to me in recv $WAN
ipfw -q add 390 nat 1 ip4 from any to any out xmit $WAN
ipfw -q add 10000 allow ip from any to any
```

Forwarding:

```sh
sysctl net.inet.ip.forwarding=1
sysctl net.inet6.ip6.forwarding=1
```

OpenBSD PF:

```sh
# don't know how to rdr-to from local system. doesn't seem to work. only works for routed traffic.
# /etc/pf.conf
pass in quick on em1 inet  proto tcp to port {80,443} rdr-to 127.0.0.1 port 988
pass in quick on em1 inet6 proto tcp to port {80,443} rdr-to ::1 port 988
pfctl -f /etc/pf.conf
/opt/zapret/tpws/tpws --port=988 --user=daemon --bind-addr=::1 --bind-addr=127.0.0.1

# dvtws works both for routed and local

pass in  quick on em0 proto tcp from port {80,443} flags SA/SA divert-packet port 989 no state
pass in  quick on em0 proto tcp from port {80,443} no state
pass out quick on em0 proto tcp to   port {80,443} divert-packet port 989 no state
pfctl -f /etc/pf.conf
./dvtws --port=989 --dpi-desync=split2

# dvtws with table limitations: to zapret,zapret6 but not to nozapret,nozapret6
# reload tables: pfctl -f /etc/pf.conf
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
