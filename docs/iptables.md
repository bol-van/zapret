For window size changing:

```sh
iptables -t mangle -I PREROUTING -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 200 --queue-bypass
iptables -t mangle -I PREROUTING -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -m set --match-set zapret src -j NFQUEUE --queue-num 200 --queue-bypass
```

For `dpi-desync` attack:

```sh
iptables -t mangle -I POSTROUTING -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:6 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
iptables -t mangle -I POSTROUTING -p tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
iptables -t mangle -I POSTROUTING -p udp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass

# auto hostlist with avoiding wrong ACK numbers in RST,ACK packets sent by Russian DPI

sysctl net.netfilter.nf_conntrack_tcp_be_liberal=1
iptables -t mangle -I POSTROUTING -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:12 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
iptables -t mangle -I PREROUTING -p tcp -m multiport --sports 80,443 -m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:6 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
```

For `TPROXY`:

```sh
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

ip -f inet rule add fwmark 1 lookup 100
ip -f inet route add local default dev lo table 100

# prevent loop

iptables  -t filter -I INPUT -p tcp --dport 988  -j REJECT
iptables  -t mangle -A PREROUTING -i eth1 -p tcp --dport 80 -j MARK --set-mark 1
iptables  -t mangle -A PREROUTING -i eth1 -p tcp --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 988

iptables  -t mangle -A PREROUTING -i eth1 -p tcp --dport 80 -m set --match-set zapret dst -j MARK --set-mark 1
iptables  -t mangle -A PREROUTING -i eth1 -p tcp --dport 80 -m mark --mark 0x1/0x1 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 988
```

For DNAT:

```sh
# run tpws as user "tpws". its required to avoid loops

sysctl -w net.ipv4.conf.eth1.route_localnet=1
iptables -t nat -I PREROUTING -p tcp --dport 80 -j DNAT --to 127.0.0.127:988
iptables -t nat -I OUTPUT -p tcp --dport 80 -m owner ! --uid-owner tpws -j DNAT --to 127.0.0.127:988
```

Reset all `iptables` rules:

```sh
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X
```

Reset `iptables` policies:

```sh
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t mangle -P POSTROUTING ACCEPT
iptables -t mangle -P PREROUTING ACCEPT
iptables -t mangle -P INPUT ACCEPT
iptables -t mangle -P FORWARD ACCEPT
iptables -t mangle -P OUTPUT ACCEPT
iptables -t raw -P PREROUTING ACCEPT
iptables -t raw -P OUTPUT ACCEPT
```
