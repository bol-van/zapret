`nftables` test cheat sheet. Simplified rules to test `nfqws` and `tpws`.

For DNAT:

```sh
# run tpws as user "tpws". its required to avoid loops
nft delete table inet ztest
nft create table inet ztest
nft add chain inet ztest pre "{type nat hook prerouting priority dstnat;}"
nft add rule inet ztest pre tcp dport "{80,443}" redirect to :988
nft add chain inet ztest out "{type nat hook output priority -100;}"
nft add rule inet ztest out tcp dport "{80,443}" skuid != tpws redirect to :988
```

For `dpi-desync` attack:

```sh
nft delete table inet ztest
nft create table inet ztest
nft add chain inet ztest post "{type filter hook postrouting priority mangle;}"
nft add rule inet ztest post tcp dport "{80,443}" ct original packets 1-12 queue num 200 bypass
nft add rule inet ztest post udp dport 443 ct original packets 1-4 queue num 200 bypass

# auto hostlist with avoiding wrong ACK numbers in RST,ACK packets sent by Russian DPI

sysctl net.netfilter.nf_conntrack_tcp_be_liberal=1
nft add chain inet ztest pre "{type filter hook prerouting priority filter;}"
nft add rule inet ztest pre tcp sport "{80,443}" ct reply packets 1-4 queue num 200 bypass
```

* show rules: `nft list table inet ztest`,
* delete table: `nft delete table inet ztest`
