# zapret v71.2

# SCAMMER WARNING

This software is free and open source under [MIT license](./LICENSE.txt).
If anyone demands you to download this software only from their webpage, telegram channel, forces you to delete links, videos, makes copyright claims, you are dealing with scammers.
However, [donations](#donations) are welcome.

# Multilanguage/Мультиязычный README
___
[![en](https://img.shields.io/badge/lang-en-red.svg)](https://github.com/bol-van/zapret/tree/master/docs/readme.en.md)
[![ru](https://img.shields.io/badge/lang-ru-green.svg)](https://github.com/bol-van/zapret/tree/master/docs/readme.md)

***

- [What is it for](#what-is-it-for)
- [How it works](#how-it-works)
- [How to put this into practice in the linux system](#how-to-put-this-into-practice-in-the-linux-system)
- [When it will not work](#when-it-will-not-work)
- [nfqws](#nfqws)
  - [DPI desync attack](#dpi-desync-attack)
  - [Fakes](#fakes)
  - [Fake mods](#fake-mods)
  - [TCP segmentation](#tcp-segmentation)
  - [Sequence numbers overlap](#sequence-numbers-overlap)
  - [ipv6 specific modes](#ipv6-specific-modes)
  - [Original modding](#original-modding)
  - [Duplicates](#duplicates)
  - [Server reply reaction](#server-reply-reaction)
  - [SYNDATA mode](#syndata-mode)
  - [DPI desync combos](#dpi-desync-combos)
  - [IP cache](#ip-cache)
  - [CONNTRACK](#conntrack)
  - [Reassemble](#reassemble)
  - [UDP support](#udp-support)
  - [IP fragmentation](#ip-fragmentation)
  - [Multiple strategies](#multiple-strategies)
  - [WIFI filtering](#wifi-filtering)
  - [Virtual machines](#virtual-machines)
  - [IPTABLES for nfqws](#iptables-for-nfqws)
  - [NFTABLES for nfqws](#nftables-for-nfqws)
  - [Flow offloading](#flow-offloading)
  - [Server side fooling](#server-side-fooling)
- [tpws](#tpws)
  - [TCP segmentation in tpws](#tcp-segmentation-in-tpws)
  - [TLSREC](#tlsrec)
  - [MSS](#mss)
  - [Other tamper options](#other-tamper-options)
  - [Supplementary options](#supplementary-options)
  - [Multiple strategies](#multiple-strategies-1)
  - [IPTABLES for tpws](#iptables-for-tpws)
  - [NFTABLES for tpws](#nftables-for-tpws)
- [Ways to get a list of blocked IP](#ways-to-get-a-list-of-blocked-ip)
- [Domain name filtering](#domain-name-filtering)
- [**autohostlist** mode](#autohostlist-mode)
- [Choosing parameters](#choosing-parameters)
- [Screwing to the firewall control system or your launch system](#screwing-to-the-firewall-control-system-or-your-launch-system)
- [Installation](#installation)
  - [Checking ISP](#checking-isp)
  - [desktop linux system](#desktop-linux-system)
  - [OpenWRT](#openwrt)
  - [Android](#android)
  - [FreeBSD, OpenBSD, MacOS](#freebsd-openbsd-macos)
  - [Windows (WSL)](#windows-wsl)
  - [Other devices](#other-devices)
- [Donations](#donations)
***

## What is it for

A stand-alone (without 3rd party servers) DPI circumvention tool.
May allow to bypass http(s) website blocking or speed shaping, resist signature tcp/udp protocol discovery.

The project is mainly aimed at the Russian audience.
Some features of the project are russian reality specific (such as getting list of sites
blocked by Roskomnadzor), but most others are common.

Mainly OpenWRT targeted but also supports traditional Linux, FreeBSD, OpenBSD, Windows, partially MacOS.

Most features are also supported in Windows.

## How it works

In the simplest case you are dealing with passive DPI. Passive DPI can read passthrough traffic,
inject its own packets, but cannot drop packets.

If the request is prohibited the passive DPI will inject its own RST packet and optionally http redirect packet.

If fake packets from DPI are only sent to client, you can use iptables commands to drop them if you can write
correct filter rules. This requires manual in-deep traffic analysis and tuning for specific ISP.

This is how we bypass the consequences of a ban trigger.

If the passive DPI sends an RST packet also to the server, there is nothing you can do about it.
Your task is to prevent ban trigger from firing up. Iptables alone will not work.
This project is aimed at preventing the ban rather than eliminating its consequences.

To do that send what DPI does not expect and what breaks its algorithm of recognizing requests and blocking them.

Some DPIs cannot recognize the http request if it is divided into TCP segments.
For example, a request of the form `GET / HTTP / 1.1 \ r \ nHost: kinozal.tv ......`
we send in 2 parts: first go `GET`, then `/ HTTP / 1.1 \ r \ nHost: kinozal.tv .....`.

Other DPIs stumble when the `Host:` header is written in another case: for example, `host:`.

Sometimes work adding extra space after the method: `GET /` => `GET  /`
or adding a dot at the end of the host name: `Host: kinozal.tv.`

There is also more advanced magic for bypassing DPI at the packet level.

## How to put this into practice in the linux system

In short, the options can be classified according to the following scheme:

1. Passive DPI not sending RST to the server. ISP tuned iptables commands can help.
This option is out of the scope of the project. If you do not allow ban trigger to fire, then you won’t have to
deal with its consequences.
2. Modification of the TCP connection at the stream level. Implemented through a proxy or transparent proxy.
3. Modification of TCP connection at the packet level. Implemented through the NFQUEUE handler and raw sockets.

For options 2 and 3, **tpws** and **nfqws** programs are implemented, respectively.
You need to run them with the necessary parameters and redirect certain traffic with iptables or nftables.

## When it will not work

* If DNS server returns false responses. ISP can return false IP addresses or not return anything
when blocked domains are queried. If this is the case change DNS to public ones, such as 8.8.8.8 or 1.1.1.1.Sometimes ISP hijacks queries to any DNS server. Dnscrypt or dns-over-tls help.
* If blocking is done by IP.
* If a connection passes through a filter capable of reconstructing a TCP connection, and which
follows all standards. For example, we are routed to squid. Connection goes through the full OS tcpip stack. This project targets DPI only, not full OS stack and not server applications.

## nfqws

This program is a packet modifier and a NFQUEUE queue handler.
For BSD systems there is dvtws. Its built from the same source and has almost the same parameters (see [bsd.en.md](./bsd.en.md)).
nfqws takes the following parameters:

```
 @<config_file>					; read file for options. must be the only argument. other options are ignored.

 --debug=0|1
 --dry-run                                      ; verify parameters and exit with code 0 if successful
 --version                                      ; print version and exit
 --comment                                      ; any text (ignored)
 --qnum=<nfqueue_number>
 --daemon                                       ; daemonize
 --pidfile=<filename>                           ; write pid to file
 --user=<username>                              ; drop root privs
 --uid=uid[:gid1,gid2,...]                      ; drop root privs
 --bind-fix4                                    ; apply outgoing interface selection fix for generated ipv4 packets
 --bind-fix6                                    ; apply outgoing interface selection fix for generated ipv6 packets
 --wsize=<window_size>[:<scale_factor>]         ; set window size. 0 = do not modify. OBSOLETE !
 --wssize=<window_size>[:<scale_factor>]        ; set window size for server. 0 = do not modify. default scale_factor = 0.
 --wssize-cutoff=[n|d|s]N                       ; apply server wsize only to packet numbers (n, default), data packet numbers (d), relative sequence (s) less than N
 --ctrack-timeouts=S:E:F[:U]                    ; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default 60:300:60:60
 --ctrack-disable=[0|1]                         ; 1 or no argument disables conntrack
 --ipcache-lifetime=<int>                       ; time in seconds to keep cached hop count and domain name (default 7200). 0 = no expiration
 --ipcache-hostname=[0|1]                       ; 1 or no argument enables ip->hostname caching
 --hostcase                                     ; change Host: => host:
 --hostspell                                    ; exact spelling of "Host" header. must be 4 chars. default is "host"
 --hostnospace                                  ; remove space after Host: and add it to User-Agent: to preserve packet size
 --domcase                                      ; mix domain case : Host: TeSt.cOm
 --methodeol					; add '\n' before method and remove space after Host:
 --synack-split=[syn|synack|acksyn]             ; perform TCP split handshake : send SYN only, SYN+ACK or ACK+SYN
 --orig-ttl=<int>                               ; set TTL for original packets
 --orig-ttl6=<int>                              ; set ipv6 hop limit for original packets. by default ttl value is used
 --orig-autottl=[<delta>[:<min>[-<max>]]|-]     ; auto ttl mode for both ipv4 and ipv6. default: +5:3-64. "0:0-0" or "-" disables autottl.
 --orig-autottl6=[<delta>[:<min>[-<max>]]|-]    ; overrides --orig-autottl for ipv6 only
 --orig-mod-start=[n|d|s]N                      ; apply orig TTL mod to packet numbers (n, default), data packet numbers (d), relative sequence (s) greater or equal than N
 --orig-mod-cutoff=[n|d|s]N                     ; apply orig TTL mod to packet numbers (n, default), data packet numbers (d), relative sequence (s) less than N
 --dup=<int>                                    ; duplicate original packets. send N dups before original.
 --dup-replace=[0|1]                            ; 1 or no argument means do not send original, only dups
 --dup-ttl=<int>                                ; set TTL for dups
 --dup-ttl6=<int>                               ; set ipv6 hop limit for dups. by default ttl value is used
 --dup-autottl=[<delta>[:<min>[-<max>]]|-]      ; auto ttl mode for both ipv4 and ipv6. default: -1:3-64. "0:0-0" or "-" disables autottl.
 --dup-autottl6=[<delta>[:<min>[-<max>]]|-]     ; overrides --dup-autottl for ipv6 only
 --dup-fooling=<mode>[,<mode>]                  ; can use multiple comma separated values. modes : none md5sig badseq badsum datanoack hopbyhop hopbyhop2
 --dup-badseq-increment=<int|0xHEX>             ; badseq fooling seq signed increment for dup. default -10000
 --dup-badack-increment=<int|0xHEX>             ; badseq fooling ackseq signed increment for dup. default -66000
 --dup-start=[n|d|s]N                           ; apply dup to packet numbers (n, default), data packet numbers (d), relative sequence (s) greater or equal than N
 --dup-cutoff=[n|d|s]N                          ; apply dup to packet numbers (n, default), data packet numbers (d), relative sequence (s) less than N
 --dpi-desync=[<mode0>,]<mode>[,<mode2>]        ; try to desync dpi state. modes : synack fake fakeknown rst rstack hopbyhop destopt ipfrag1 multisplit multidisorder fakedsplit fakeddisorder ipfrag2 udplen tamper
 --dpi-desync-fwmark=<int|0xHEX>                ; override fwmark for desync packet. default = 0x40000000 (1073741824)
 --dpi-desync-ttl=<int>                         ; set ttl for desync packet
 --dpi-desync-ttl6=<int>                        ; set ipv6 hop limit for desync packet. by default ttl value is used.
 --dpi-desync-autottl=[<delta>[:<min>[-<max>]]|-]  ; auto ttl mode for both ipv4 and ipv6. default: -1:3-20. "0:0-0" or "-" disables autottl.
 --dpi-desync-autottl6=[<delta>[:<min>[-<max>]]|-] ; overrides --dpi-desync-autottl for ipv6 only
 --dpi-desync-fooling=<mode>[,<mode>]           ; can use multiple comma separated values. modes : none md5sig ts badseq badsum datanoack hopbyhop hopbyhop2
 --dpi-desync-repeats=<N>                       ; send every desync packet N times
 --dpi-desync-skip-nosni=0|1                    ; 1(default)=do not act on ClientHello without SNI (ESNI ?)
 --dpi-desync-split-pos=N|-N|marker+N|marker-N  ; comma separated list of split positions
                                                ; markers: method,host,endhost,sld,endsld,midsld,sniext
                                                ; full list is only used by multisplit and multidisorder
                                                ; fakedsplit/fakeddisorder use first l7-protocol-compatible parameter if present, first abs value otherwise
 --dpi-desync-split-seqovl=N|-N|marker+N|marker-N ; use sequence overlap before first sent original split segment
 --dpi-desync-split-seqovl-pattern=<filename>|0xHEX ; pattern for the fake part of overlap
 --dpi-desync-fakedsplit-pattern=<filename>|0xHEX ; fake pattern for fakedsplit/fakeddisorder
 --dpi-desync-ipfrag-pos-tcp=<8..9216>          ; ip frag position starting from the transport header. multiple of 8, default 8.
 --dpi-desync-ipfrag-pos-udp=<8..9216>          ; ip frag position starting from the transport header. multiple of 8, default 32.
 --dpi-desync-badseq-increment=<int|0xHEX>      ; badseq fooling seq signed increment. default -10000
 --dpi-desync-badack-increment=<int|0xHEX>      ; badseq fooling ackseq signed increment. default -66000
 --dpi-desync-any-protocol=0|1                  ; 0(default)=desync only http and tls  1=desync any nonempty data packet
 --dpi-desync-fake-http=<filename>|0xHEX        ; file containing fake http request
 --dpi-desync-fake-tls=<filename>|0xHEX|!       ; file containing fake TLS ClientHello (for https). '!' = standard fake
 --dpi-desync-fake-tls-mod=mod[,mod]            ; comma separated list of TLS fake mods. available mods : none,rnd,rndsni,sni=<sni>,dupsid,padencap
 --dpi-desync-fake-unknown=<filename>|0xHEX     ; file containing unknown protocol fake payload
 --dpi-desync-fake-syndata=<filename>|0xHEX     ; file containing SYN data payload
 --dpi-desync-fake-quic=<filename>|0xHEX        ; file containing fake QUIC Initial
 --dpi-desync-fake-wireguard=<filename>|0xHEX   ; file containing fake wireguard handshake initiation
 --dpi-desync-fake-dht=<filename>|0xHEX         ; file containing fake DHT (d1..e)
 --dpi-desync-fake-discord=<filename>|0xHEX     ; file containing fake Discord voice connection initiation packet (IP Discovery)
 --dpi-desync-fake-stun=<filename>|0xHEX        ; file containing fake STUN message
 --dpi-desync-fake-unknown-udp=<filename>|0xHEX ; file containing unknown udp protocol fake payload
 --dpi-desync-udplen-increment=<int>            ; increase or decrease udp packet length by N bytes (default 2). negative values decrease length.
 --dpi-desync-udplen-pattern=<filename>|0xHEX   ; udp tail fill pattern
 --dpi-desync-start=[n|d|s]N                    ; apply dpi desync only to packet numbers (n, default), data packet numbers (d), relative sequence (s) greater or equal than N
 --dpi-desync-cutoff=[n|d|s]N                   ; apply dpi desync only to packet numbers (n, default), data packet numbers (d), relative sequence (s) less than N
 --hostlist=<filename>                          ; apply dpi desync only to the listed hosts (one host per line, subdomains auto apply if not prefixed with `^`, gzip supported, multiple hostlists allowed)
 --hostlist-domains=<domain_list>               ; comma separated fixed domain list
 --hostlist-exclude=<filename>                  ; do not apply dpi desync to the listed hosts (one host per line, subdomains auto apply if not prefixed with `^`, gzip supported, multiple hostlists allowed)
 --hostlist-exclude-domains=<domain_list>       ; comma separated fixed domain list
 --hostlist-auto=<filename>                     ; detect DPI blocks and build hostlist automatically
 --hostlist-auto-fail-threshold=<int>           ; how many failed attempts cause hostname to be added to auto hostlist (default : 3)
 --hostlist-auto-fail-time=<int>                ; all failed attemps must be within these seconds (default : 60)
 --hostlist-auto-retrans-threshold=<int>        ; how many request retransmissions cause attempt to fail (default : 3)
 --hostlist-auto-debug=<logfile>                ; debug auto hostlist positives
 --new                                          ; begin new strategy (new profile)
 --skip                                         ; do not use this profile
 --filter-l3=ipv4|ipv6                          ; L3 protocol filter. multiple comma separated values allowed.
 --filter-tcp=[~]port1[-port2]|*                ; TCP port filter. ~ means negation. setting tcp and not setting udp filter denies udp. comma separated list supported.
 --filter-udp=[~]port1[-port2]|*                ; UDP port filter. ~ means negation. setting udp and not setting tcp filter denies tcp. comma separated list supported.
 --filter-l7=<proto>                            ; L6-L7 protocol filter. multiple comma separated values allowed. proto: http tls quic wireguard dht discord stun unknown
 --filter-ssid=ssid1[,ssid2,ssid3,...]          ; per profile wifi SSID filter
 --ipset=<filename>                             ; ipset include filter (one ip/CIDR per line, ipv4 and ipv6 accepted, gzip supported, multiple ipsets allowed)
 --ipset-ip=<ip_list>                           ; comma separated fixed subnet list
 --ipset-exclude=<filename>                     ; ipset exclude filter (one ip/CIDR per line, ipv4 and ipv6 accepted, gzip supported, multiple ipsets allowed)
 --ipset-exclude-ip=<ip_list>                   ; comma separated fixed subnet list
```

### DPI desync attack

The idea is to take original message, modify it, add additional fake information in such a way that the server OS accepts original data only
but DPI cannot recostruct original message or sees what it cannot identify as a prohibited request.

There's a set of instruments to achieve that goal.
It can be fake packets that reach DPI but do not reach server or get rejected by server, TCP segmentation or IP fragmentation.
There're attacks based on TCP sequence numbers. Methods can be combined in many ways.

### Fakes

Fakes are separate generated by nfqws packets carrying false information for DPI. They must either not reach the server or be rejected by it. Otherwise TCP connection or data stream would be broken. There're multiple ways to solve this task.

* **md5sig** does not work on all servers. It typically works only on Linux servers. MD5 tcp option requires additional space in TCP header
  and can cause MTU overflow during fakedsplit/fakeddisorder on low positions when multisegment query (TLS kyber) is transmitted.
  `nfqws` cannot redistribute data between original TCP segments. The error displayed is 'message too long'.
* **badsum** doesn't work if your device is behind NAT which does not pass invalid packets.
  The most common Linux NAT router configuration does not pass them. Most home routers are Linux based.
  The default sysctl configuration `net.netfilter.nf_conntrack_checksum=1` causes contrack to verify tcp and udp checksums
  and set INVALID state for packets with invalid checksum.
  Typically, iptables rules include a rule for dropping packets with INVALID state in the FORWARD chain.
  The combination of these factors does not allow badsum packets to pass through the router.
  In openwrt mentioned sysctl is set to 0 from the box, in other routers its often left in the default "1" state.
  For nfqws to work properly through the router set `net.netfilter.nf_conntrack_checksum=0` on the router.
  System never verifies checksums of locally generated packets so nfqws will always work on the router itself.
  If you are behind another NAT, such as a ISP, and it does not pass invalid packages, there is nothing you can do about it.
  But usually ISPs pass badsum.
  Some adapters/switches/drivers enable hardware filtering of rx badsum not allowing it to pass to the OS.
  This behavior was observed on a Mediatek MT7621 based device.
  Tried to modify mediatek ethernet driver with no luck, likely hardware enforced limitation.
  However the device allowed to send badsum packets, problem only existed for passthrough traffic from clients.
* **badseq** packets will be dropped by server, but DPI also can ignore them.
  default badseq increment is set to -10000 because some DPIs drop packets outside of the small tcp window.
  But this also can cause troubles when `--dpi-desync-any-protocol` is enabled.
  To be 100% sure fake packet cannot fit to server tcp window consider setting badseq increment to 0x80000000
* **TTL** looks like the best option, but it requires special tuning for each ISP. If DPI is further than local ISP websites
  you can cut access to them. Manual IP exclude list is required. Its possible to use md5sig with ttl.
  This way you cant hurt anything, but good chances it will help to open local ISP websites.
  If automatic solution cannot be found then use `zapret-hosts-user-exclude.txt`.
  Some router stock firmwares fix outgoing TTL. Without switching this option off TTL fooling will not work.
* **hopbyhop** is ipv6 only. This fooling adds empty extension header `hop-by-hop options` or two headers in case of `hopbyhop2`.
  Packets with two hop-by-hop headers violate RFC and discarded by all operating systems.
  All OS accept packets with one hop-by-hop header.
  Some ISPs/operators drop ipv6 packets with hop-by-hop options. Fakes will not be processed by the server either because
  ISP drops them or because there are two same headers.
  DPIs may still anaylize packets with one or two hop-by-hop headers.
* **datanoack** sends tcp fakes without ACK flag. Servers do not accept this but DPI may accept.
  This mode may break NAT and may not work with iptables if masquerade is used, even from the router itself.
  Works with nftables properly. Likely requires external IP address (some ISPs pass these packets through their NAT).
* **autottl** tries to automatically guess hop count to the server and compute TTL by adding some delta value that can be positive or negative.
  Positive deltas must be preceeded by unary `+` sign. Deltas without any unary sign are treated negative for old versions compatibility reasons.
  This tech relies on well known TTL default values used by OS : 64,128,255.
  nfqws needs first incoming packet to see it's TTL. You must redirect it too.
  If resulting value TTL is outside the range (min,max) then its normalized to min or max.
  If delta is negative and TTL is longer than guessed hop count or delta is positive and TTL is shorter than guessed hop count
  then autottl fails and falls back to the fixed value.
  This can help if multiple DPIs exists on backbone channels, not just near the ISP.
  Can fail if inbound and outbound paths are not symmetric.


`--dpi-desync-fooling` takes multiple comma separated values.


Multiple parameters `--dpi-desync-fake-???` are supported except for the `--dpi-desync-fake-syndata`.
Fakes are sent in the specified order. `--dpi-desync-repeats` resends each fake.
Resulting order would be : `fake1 fake1 fake1 fake2 fake2 fake2 fake3 fake3 fake3 .....`


### FAKE mods

**nfqws** has built-in TLS fake. It can be customized with `--dpi-desync-fake-tls` option.
Customized fake data can be anything - valid TLS Client Hello or arbitrary data.
It's possible to use TLS Client Hello with any fingerprint and any SNI.

**nfqws** can do some modifications of valid TLS Client Hello fakes in runtime with `--dpi-desync-fake-tls-mod` option.

 * `none`. Do not do any mods.
 * `rnd`. Randomize `random` and `session id` fields. Applied on every request.
 * `rndsni`. Randomize SNI. If SNI >=7 symbols random SLD is applied with known TLD. Otherwise filled with random symbols. Applied only once at startup.
 * `dupsid`. Copy `session ID` from original TLS Client Hello. Takes precedence over `rnd`. Applied on every request.
 * `sni=<sni>`. Set specified SNI value. Changes TLS fake length, fixes lengths in TLS structure. Applied once at startup before `rndsni`.
 * `padencap`. Padding extension is extended by original TLS Client Hello size (including multi packet variation with kyber). Padding extension is added to the end if not present, otherwise it must be the last extension. All lengths are increased. Fake size is not changed. Can be useful if DPI does not analyze sequence numbers properly. Applied on every request.

By default if custom fake is not defined `rnd,rndsni,dupsid` mods are applied. If defined - `none`.
This behaviour is compatible with previous versions with addition of `dupsid`.

If multiple TLS fakes are present each one takes the last mod.
If a mod is specified after fake it replaces previous mod.
This way it's possible to use different mods for every TLS fake.

If a mod is set to non-TLS fake it causes error. Use `--dpi-desync-fake-tls-mod=none'.

Example : `--dpi-desync-fake-tls=iana_org.bin --dpi-desync-fake-tls-mod=rndsni --dpi-desync-fake-tls=0xaabbccdd --dpi-desync-fake-tls-mod=none'

### TCP segmentation

 * `multisplit`. split request at specified in `--dpi-desync-split-pos` positions
 * `multidisorder`. same as `multisplit` but send in reverse order
 * `fakedsplit`. split request into 2 segments adding fakes in the middle of them : fake 1st segment, 1st segment, fake 1st segment, fake 2nd segment, 2nd segment, fake 2nd segment
 * `fakeddisorder`. same as `fakedsplit` but with another order : fake 2nd segment, 2nd segment, fake 2nd segment, fake 1st segment, 1st segment, fake 1st segment

Positions are defined by markers.

* **Absolute positive marker** - numeric offset inside one packet or group of packets starting from the start
* **Absolute negative marker** - numeric offset inside one packet or group of packets starting from the next byte after the end
* **Relative marker** - positive or negative offset relative to a logical position within a packet or group of packets

Relative positions :

* **method** - HTTP method start ('GET', 'POST', 'HEAD', ...). Method is usually always at position 0 but can shift because of `--methodeol` fooling. If fooled position can become 1 or 2.
* **host** - hostname start in a known protocol (http, TLS)
* **endhost** - the byte next to the last hostname's byte
* **sld** - second level domain start in the hostname
* **endsld** - the byte next to the last SLD byte
* **midsld** - middle of SLD
* **sniext** - start of the data field in the SNI TLS extension. Any extension has 2-byte type and length fields followed by data field.

Marker list example : `100,midsld,sniext+1,endhost-2,-10`.

When splitting all markers are resolved to absolute offsets. If a relative position is absent in the current protocol its dropped. Then all resolved offsets are normalized to the current packet offset in multi packet group (multi-packet TLS with kyber, for example). Positions outside of the current packet are dropped. Remaining positions are sorted and deduplicated.

In `multisplit`or `multidisorder` case split is cancelled if no position remained.

`fakedsplit` и `fakeddisorder` use only one split position. It's searched from the  `--dpi-desync-split-pos` list by a special alorightm.
First relative markers are searched. If no suitable found absolute markers are searched. If nothing found position 1 is used.

For example, `--dpi-desync-split-pos=method+2,midsld,5` means `method+2` for http, `midsld` for TLS and 5 for others.

### Sequence numbers overlap

`seqovl` adds to one of the original segment `seqovl` bytes to the beginning and decreases sequence number. For `split` - to the first segment, for `disorder` - to the beginning of the penultimate segment sent (second in the original sequence).

In `split` mode this creates partially in-window packet. OS receives only in-window part.
In `disorder` mode OS receives fake and real part of the second segment but does not pass received data to the socket until first segment is received. First segment overwrites fake part of the second segment. Then OS passes original data to the socket.
All unix OS except Solaris preserve last received data. This is not the case for Windows servers and `disorder` with `seqovl` will not work.
Disorder requires `seqovl` to be less than split position. Otherwise `seqovl` is not possible and will be cancelled.
Method allows to avoid separate fakes. Fakes and real data are mixed.

### ipv6 specific modes

`hopbyhop`, `destopt` and `ipfrag1` desync modes (they're not the same as `hopbyhop` fooling !) are ipv6 only. One `hop-by-hop`,
`destination options` or `fragment` header is added to all desynced packets.
Extra header increases packet size and can't be applied to the maximum size packets.
If it's not possible to send modified packet original one will be sent.
The idea here is that DPI sees 0 in the next header field of the main ipv6 header and does not
walk through the extension header chain until transport header is found.
`hopbyhop`, `destopt`, `ipfrag1` modes can be used with any second phase mode except `ipfrag1+ipfrag2`.
For example, `hopbyhop,multisplit` means split original tcp packet into several pieces and add hop-by-hop header to each.
With `hopbyhop,ipfrag2` header sequence will be : `ipv6,hop-by-hop,fragment,tcp/udp`.
`ipfrag1` mode may not always work without special preparations. See "IP Fragmentation" notices.

### Original modding

Parameters `--orig-ttl` and `--orig-ttl6` allow to set TTL on original packets.
All further packet manipulations, e.g. segmentation, take modded original as data source and inherit modded TTL.

`--orig-autottl` and `--orig-autottl6` work the same way as `dpi-desync-autottl`, but on original packets.
Delta should have unary `+` sign to produce TTL longer than guessed hop count. Otherwise nothing will reach the server.
Example : `--orig-autottl=+5:3-64`.

`--orig-mod-start` and `--orig-mod-cutoff` specify start and end conditions for original modding. The work the same way as
`--dpi-desync-start` and `--dpi-desync-cutoff`.

This function can be useful when DPI hunts for fakes and blocks suspicious connections.
DPI can compute TTL difference between packets and fire block trigger if it exceedes some threshold.

### Duplicates

Duplicates are copies of original packets which are sent before them. Duplicates are enabled by `--dup=N`, where N is dup count.
`--dup-replace` disables sending of original.

Dups are sent only when original would also be sent without reconstruction.
For example, if TCP segmentation happens, original is actually dropped and is being replaced by artificially constructed new packets.
Dups are not sent in this case.

All dup fooling modes are available : `--dup-ttl`. `--dup-ttl6`, `--dup-fooling`.
You decide whether these packets need to reach the server and in what form, according to the intended strategy.

`--dup-autottl` and `--dup-autottl6` work the same way as `dpi-desync-autottl`.
Delta can be preceeded by unary `+` or `-` sign.
Example : `--dup-autottl=-2:3-64`.

`--dup-start` and `--dup-cutoff` specify start and end conditions for dupping. The work the same way as
`--dpi-desync-start` and `--dpi-desync-cutoff`.

This function can help if DPI compares some characteristics of fake and original packets and block connection if they differ some way.
Fooled duplicates can convince DPI that the whole session has an anomaly.
For example, all connection is protected by MD5 signature, not individual packets.

### Server reply reaction

There are DPIs that analyze responses from the server, particularly the certificate from the ServerHello that contain domain name(s). The ClientHello delivery confirmation is an ACK packet from the server with ACK sequence number corresponding to the length of the ClientHello+1.
In the disorder variant, a selective acknowledgement (SACK) usually arrives first, then a full ACK.
If, instead of ACK or SACK, there is an RST packet with minimal delay, DPI cuts you off at the request stage.
If the RST is after a full ACK after a delay of about ping to the server, then probably DPI acts on the server response. The DPI may be satisfied with good ClientHello and stop monitoring the TCP session without checking ServerHello. Then you were lucky. 'fake' option could work.
If it does not stop monitoring and persistently checks the ServerHello, --wssize parameter may help (see [CONNTRACK](#conntrack)).
Otherwise it is hardly possible to overcome this without the help of the server.
The best solution is to enable TLS 1.3 support on the server. TLS 1.3 sends the server certificate in encrypted form.
This is recommendation to all admins of blocked sites. Enable TLS 1.3. You will give more opportunities to overcome DPI.

### SYNDATA mode

Normally SYNs come without data payload. If it's present it's ignored by all major OS if TCP fast open (TFO) is not involved, but may not be ignored by DPI.
Original connections with TFO are not touched because otherwise they would be definitely broken.
Without extra parameter payload is 16 zero bytes.

### DPI desync combos

`--dpi-desync` takes up to 3 comma separated modes.

* 0 phase modes work during the connection establishement : `synack`, `syndata` `--wsize`, `--wssize`. [hostlist](#multiple-strategies) filters are applicable only if [`--ipcache-hostname`](#ip-cache) is enabled.
* In the 1st phase fakes are sent before original data  : `fake`, `rst`, `rstack`.
* In the 2nd phase original data is sent in a modified way (for example `fakedsplit` or `ipfrag2`).

Modes must be specified in phase ascending order.

### IP cache

`ipcache` is the structure in the process memory that stores some information by IP address and interface name key.
This information can be used as missing data. Currently it's used in the following cases :

1. IP,interface => hop count . This is used to apply autottl at 0 phase since the first session packet. If the record is absent autottl will not be applied immediately. Second time it will be applied immediately using cached hop count.

2. IP => hostname . Hostname is cached to be used in 0 phase strategies. Mode is disabled by default and can be enabled by `ipcache-hostname` parameter.
This tech is experimental. There's no one-to-one correspondence between IP and domain name. Multiple domains can resolve to the same IP.
If collision happens hostname is replaced. On CDNs a domain can resolve to different IPs over time. `--ipcache-lifetime` limits how long cached record is valid. It's 2 hours by default.
Be prepared for unexpected results that can be explained only by reading debug logs.

SIGUSR2 forces process to output it's ipcache to stdout.

### CONNTRACK

nfqws is equipped with minimalistic connection tracking system (conntrack)
It's used if some specific DPI circumvention methods are involved and helps to reassemble multi-packet requests.

Conntrack can track connection phase : SYN,ESTABLISHED,FIN , packet counts in both directions , sequence numbers.

It can be fed with unidirectional or bidirectional packets.

A SYN or SYN,ACK packet creates an entry in the conntrack table.

That's why iptables redirection must start with the first packet although can be cut later using connbytes filter.

First seen UDP packet creates UDP stream. It defines the stream direction. Then all packets with the same
`src_ip,src_port,dst_ip,dst_port` are considered to belong to the same UDP stream. UDP stream exists till inactivity timeout.

A connection is deleted from the table as soon as it's no more required to satisfy nfqws needs or when a timeout happens.

There're 3 timeouts for each connection state. They can be changed in `--ctrack-timeouts` parameter.

`--wssize` changes tcp window size for the server to force it to send split replies.
In order for this to affect all server operating systems, it is necessary to change the window size in each outgoing packet
before sending the message, the answer to which must be split (for example, TLS ClientHello).
That's why conntrack is required to know when to stop applying low window size.

If you do not stop and set the low wssize all the time, the speed will drop catastrophically.
Linux can overcome this using connbytes filter but other OS may not include similar filter.

In http(s) case wssize stops after the first http request or TLS ClientHello.

If you deal with a non-http(s) protocol you need `--wssize-cutoff`. It sets the threshold where wssize stops.

Threshold can be prefixed with 'n' (packet number starting from 1), 'd' (data packet number starting from 1), 
's' (relative sequence number - sent by client bytes + 1).

If a http request or TLS ClientHello packet is detected wssize stops immediately ignoring wssize-cutoff option.

If your protocol is prone to long inactivity, you should increase ESTABLISHED phase timeout using `--ctrack-timeouts`.

Default timeout is low - only 5 mins.

Don't forget that nfqws feeds with redirected packets. If you have limited redirection with connbytes
ESTABLISHED entries can remain in the table until dropped by timeout.

To diagnose conntrack state send SIGUSR1 signal to nfqws : `killall -SIGUSR1 nfqws`.

nfqws will dump current conntrack table to stdout.

Typically, in a SYN packet, client sends TCP extension **scaling factor** in addition to window size.
scaling factor is the power of two by which the window size is multiplied : 0=>1, 1=>2, 2=>4, ..., 8=>256, ...

The wssize parameter specifies the scaling factor after a colon.

Scaling factor can only decrease, increase is blocked to prevent the server from exceeding client's window size.

To force a TLS server to fragment ServerHello message to avoid hostname detection on DPI use `--wssize=1:6`

The main rule is to set scale_factor as much as possible so that after recovery the final window size
becomes the possible maximum. If you set `scale_factor` 64:0, it will be very slow.

On the other hand, the server response must not be large enough for the DPI to find what it is looking for.

`--wssize` is not applied in desync profiles with hostlist filter because it works since the connection initiation when it's not yet possible
to extract the host name. But it works with auto hostlist profiles.

`--wssize` may slow down sites and/or increase response time. It's desired to use another methods if possible.

`--dpi-desync-cutoff` allows you to set the threshold at which it stops applying dpi-desync.
Can be prefixed with 'n', 'd', 's' symbol the same way as `--wssize-cutoff`.
Useful with `--dpi-desync-any-protocol=1`.
If the connection falls out of the conntrack and `--dpi-desync-cutoff` is set, `dpi desync` will not be applied.

Set conntrack timeouts appropriately.

### Reassemble

nfqws supports reassemble of TLS and QUIC ClientHello.
They can consist of multiple packets if kyber crypto is used (default starting from chromium 124).
Chromium randomizes TLS fingerprint. SNI can be in any packet or in-between.
Stateful DPIs usually reassemble all packets in the request then apply block decision.
If nfqws receives a partial ClientHello it begins reassemble session. Packets are delayed until it's finished.
Then they go through desync using fully reassembled message.
On any error reassemble is cancelled and all delayed packets are sent immediately without desync.

There is special support for all tcp split options for multi segment TLS. Split position is treated as message-oriented, not packet oriented. For example, if your client sends TLS ClientHello with size 2000 and SNI is at 1700, desync mode is `fake,multisplit`, then fake is sent first, then original first segment and the last splitted segment. 3 segments total.

### UDP support

UDP attacks are limited. Its not possible to fragment UDP on transport level, only on network (ip) level.
Only desync modes `fake`,`fakeknown`,`hopbyhop`,`destopt`,`ipfrag1`,`ipfrag2`,`udplen` and `tamper` are applicable.
`fake`,`fakeknown`,`hopbyhop`,`destopt`,`ipfrag1` are 1st phase modes, others - 2nd phase.
As always it's possible to combine one mode from 1st phase with one mode from 2nd phase but not possible to mix same phase modes.

`udplen` increases udp payload size by `--dpi-desync-udplen-increment` bytes. Padding is filled with zeroes by default but can be overriden with a pattern.
This option can resist DPIs that track outgoing UDP packet sizes.
Requires that application protocol does not depend on udp payload size.

QUIC initial packets are recognized. Decryption and hostname extraction is supported so `--hostlist` parameter will work.
Wireguard handshake initiation, DHT, STUN and [Discord Voice IP Discovery](https://discord.com/developers/docs/topics/voice-connections#ip-discovery) packets are also recognized.
For other protocols desync use `--dpi-desync-any-protocol`.

Conntrack supports udp. `--dpi-desync-cutoff` will work. UDP conntrack timeout can be set in the 4th parameter of `--ctrack-timeouts`.

Fake attack is useful only for stateful DPI and useless for stateless dealing with each packet independently.
By default fake payload is 64 zeroes. Can be overriden using `--dpi-desync-fake-unknown-udp`.

### IP fragmentation

Modern network can be very hostile to IP fragmentation. Fragmented packets are often not delivered or refragmented/reassembled on the way. 
Frag position is set independently for tcp and udp. By default 24 and 8, must be multiple of 8.
Offset starts from the transport header.

tcp fragments are almost always filtered. It's absolutely not suitable for arbitrary websites.
udp fragments have good chances to survive but not everywhere. It's good to assume success rate on QUIC between 50..75%.
Likely more with your VPS. Sometimes filtered by DDoS protection.

There are important nuances when working with fragments in Linux.

ipv4 : Linux allows to send ipv4 fragments but standard firewall rules in OUTPUT chain can cause raw send to fail.

ipv6 : There's no way for an application to reliably send fragments without defragmentation by conntrack.
Sometimes it works, sometimes system defragments packets.
Looks like kernels <4.16 have no simple way to solve this problem. Unloading of `nf_conntrack` module
and its dependency `nf_defrag_ipv6` helps but this severely impacts functionality.
Kernels 4.16+ exclude from defragmentation untracked packets.
See `blockcheck.sh` code for example.

Sometimes it's required to load `ip6table_raw` kernel module with parameter `raw_before_defrag=1`.
In openwrt module parameters are specified after module names separated by space in files located in `/etc/modules.d`.

In traditional linux check whether `iptables-legacy` or `iptables-nft` is used. If legacy create the file
`/etc/modprobe.d/ip6table_raw.conf` with the following content :
```
options ip6table_raw raw_before_defrag=1
```
In some linux distros its possible to change current ip6tables using this command: `update-alternatives --config ip6tables`.
If you want to stay with `nftables-nft` you need to patch and recompile your version.
In `nft.c` find :
```
			{
				.name	= "PREROUTING",
				.type	= "filter",
				.prio	= -300,	/* NF_IP_PRI_RAW */
				.hook	= NF_INET_PRE_ROUTING,
			},
			{
				.name	= "OUTPUT",
				.type	= "filter",
				.prio	= -300,	/* NF_IP_PRI_RAW */
				.hook	= NF_INET_LOCAL_OUT,
			},
```
and replace -300 to -450.

It must be done manually, `blockcheck.sh` cannot auto fix this for you.

Or just move to `nftables`. You can create hooks with any priority there.

Looks like there's no way to do ipfrag using iptables for forwarded traffic if NAT is present.
`MASQUERADE` is terminating target, after it `NFQUEUE` does not work.
nfqws sees packets with internal network source address. If fragmented NAT does not process them.
This results in attempt to send packets to internet with internal IP address.
You need to use nftables instead with hook priority 101 or higher.

### Multiple strategies

**nfqws** can apply different strategies to different requests. It's done with multiple desync profiles.
Profiles are delimited by the `--new` parameter. First profile is created automatically and does not require `--new`.
Each profile has a filter. By default it's empty and profile matches any packet.
Filter can have hard parameters : ip version, ipset and tcp/udp port range.
Hard parameters are always identified unambiguously even on zero-phase when hostname and L7 are unknown yet.
Hostlists can also act as a filter. They can be combined with hard parameters.
When a packet comes profiles are matched from the first to the last until first filter condition match.
Hard filter is matched first. If it does not match verification goes to the next profile.
If a profile matches hard filter , L7 filter and has autohostlist it's selected immediately.
If a profile matches hard filter , L7 filter and has normal hostlist(s) and hostname is unknown yet verification goes to the next profile.
Otherwise profile hostlist(s) are checked for the hostname. If it matches profile is selected.
Otherwise verification goes to the next profile.

It's possible that before knowing L7 and hostname connection is served by one profile and after
this information is revealed it's switched to another profile.
If you use 0-phase desync methods think carefully what can happen during strategy switch.
Use `--debug` logging to understand better what **nfqws** does.

Profiles are numbered from 1 to N. There's last empty profile in the chain numbered 0.
It's used when no filter matched.

IMPORTANT : multiple strategies exist only for the case when it's not possible to combine all to one strategy.
Copy-pasting blockcheck results of different websites to multiple strategies lead to the mess.
This way you may never unblock all resources and only confuse yourself.

IMPORTANT : user-mode ipset implementation was not designed as a kernel version replacement. Kernel version is much more effective.
It's for the systems that lack ipset support : Windows and Linux without nftables and ipset kernel modules (Android, for example).

### WIFI filtering

Wifi interface name is not related to connected SSID.
It's possible to connect interface to different SSIDs.
They may require different strategies. How to solve this problem ?

You can run and stop nfqws instances manually. But you can also automate this.
Windows version `winws` has global filter `--ssid-filter`.
It connects or disconnects `winws` depending on connected SSIDs.
Routing is not take into account. This approach is possible because windivert can have multiple handlers with intersecting filter.
If SSID changes one `winws` connects and others disconnect.

`winws` solution is hard to implement in Linux because one nfqueue can have only one handler and it's impossible to pass same traffic to multiple queues.
One must connect when others have already disconnected.
Instead, `nfqws` has per-profile `--filter-ssid` parameter. Like `--ssid-filter` it takes comma separated SSID list.
`nfqws` maintains ifname->SSID list which is updated not faster than once a second.
When a packet comes incoming or outgoing interface name is matched to the SSID and then used in profile selection algorithm.

SSID info is taken the same way as `iw dev <ifname> info` does (nl80211).
Unfortunately it's broken since kernel 5.19 and still unfixed in 6.14.
In the latter case `iwgetid` way is used (wireless extensions).
Wireless extensions are deprecated. Some kernels can be built without wext support.
Before using `--filter-ssid` check that any of the mentioned commands can return SSID.

### Virtual machines

Most of nfqws packet magic does not work from VMs powered by virtualbox and vmware when network is NATed.
Hypervisor forcibly changes TTL and does not forward fake packets.
Set up bridge networking.

### IPTABLES for nfqws

This is the common way to redirect some traffic to nfqws :

```
iptables -t mangle -I POSTROUTING -o <wan_interface> -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:6 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
```

This variant works if DPI is stateful and does not track all packets separately in search for "bad requests". If it's stateless you have to redirect all outgoing plain http packets.

```
iptables -t mangle -I POSTROUTING -o <wan_interface> -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:6 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
iptables -t mangle -I POSTROUTING -o <wan_interface> -p tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
```

mark bit is used to prevent loops. **nfqws** sets this mark in each injected packet.
It's also necessary for correct injected packet ordering and for deadlock prevention.

`autottl` requires incoming `SYN,ACK` packet or first reply packet (it's usually the same). 

`autohostlist` needs incoming `RST` and `http redirect`.

It's possible to build tcp flags and u32 based filter but connbytes is easier.

`
iptables -t mangle -I PREROUTING -i <wan_interface> -p tcp -m multiport --sports 80,443 -m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:3 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
`

For QUIC :

```
iptables -t mangle -I POSTROUTING -o <wan_interface> -p udp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:6 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
```

6 packets cover possible retransmissions of quic initials and feed `autohostlist` mode.

### NFTABLES for nfqws

This is the start configuration :

```
IFACE_WAN=wan

nft create table inet ztest

nft add chain inet ztest post "{type filter hook postrouting priority mangle;}"
nft add rule inet ztest post oifname $IFACE_WAN meta mark and 0x40000000 == 0 tcp dport "{80,443}" ct original packets 1-6 queue num 200 bypass
nft add rule inet ztest post oifname $IFACE_WAN meta mark and 0x40000000 == 0 udp dport 443 ct original packets 1-6 queue num 200 bypass

# auto hostlist with avoiding wrong ACK numbers in RST,ACK packets sent by russian DPI
sysctl net.netfilter.nf_conntrack_tcp_be_liberal=1 
nft add chain inet ztest pre "{type filter hook prerouting priority filter;}"
nft add rule inet ztest pre iifname $IFACE_WAN tcp sport "{80,443}" ct reply packets 1-3 queue num 200 bypass
```

To engage `datanoack` or `ipfrag` for passthrough traffic special POSTNAT configuration is required. Generated packets must be marked as **notrack** in the early stage to avoid being invalidated by linux conntrack.

```
IFACE_WAN=wan

nft create table inet ztest

nft add chain inet ztest postnat "{type filter hook postrouting priority srcnat+1;}"
nft add rule inet ztest postnat oifname $IFACE_WAN meta mark and 0x40000000 == 0 tcp dport "{80,443}" ct original packets 1-6 queue num 200 bypass
nft add rule inet ztest postnat oifname $IFACE_WAN meta mark and 0x40000000 == 0 udp dport 443 ct original packets 1-6 queue num 200 bypass

nft add chain inet ztest predefrag "{type filter hook output priority -401;}"
nft add rule inet ztest predefrag "mark & 0x40000000 != 0x00000000 notrack"
```

Delete nftable :

```
nft delete table inet ztest
```

### Flow offloading

If your device supports flow offloading (hardware acceleration) iptables and nftables may not work. With offloading enabled packets bypass standard netfilter flow. It must be either disabled or selectively controlled.

Newer linux kernels have software flow offloading (SFO). The story is the same with SFO.

In `iptables` flow offloading is controlled by openwrt proprietary extension `FLOWOFFLOAD`. Newer `nftables` implement built-in offloading support.

Flow offloading does not interfere with **tpws** and `OUTPUT` traffic. It only breaks nfqws that fools `FORWARD` traffic.

### Server side fooling

It's also possible.
nfqws is intended for client side attacks. That's why it recognizes direct and reply traffic based on role in connection establishement.
If it sees SYN then source IP is client IP. If it sees SYN,ACK then source ip is server IP.
For UDP client address is considered as source IP of the first seen packet of src_ip,src_port,dst_ip,dst_port tuple.

This does not work correctly on the server side. Client traffic is reply traffic, server traffic is direct traffic.

`--wsize` works in any case. It can be used on both client and server.
Other techs work only if nfqws treats traffic as direct traffic.
To apply them to server originated traffic disable conntrack by `--ctrack-disable` parameter.
If a packet is not found in conntrack it's treated as direct and techs like `multidisorder` will be applied.

Most of the protocols will not be recognized because protocol recognition system only reacts to client packets.
To make things working use `--dpi-desync-any-protocol` with connbytes or packet payload limiter.
start/cutoff are unavailable because they are conntrack based.

`--synack-split` removes standard SYN,ACK packet and replaces it with one SYN packet, SYN then ACK separate packets or ACK then SYN separate packets.
Client sends SYN,ACK in reply which usually only server does.
This makes some DPI's to treat connection establishement roles wrong. They stop to block.
See [split handshake](https://nmap.org/misc/split-handshake.pdf).

On server side traffic should be redirected to nfqws using source port numbers and original connbytes direction.


## tpws

tpws is transparent proxy.

```
 @<config_file>                          ; read file for options. must be the only argument. other options are ignored.

 --debug=0|1|2|syslog|@<filename>        ; 1 and 2 means log to console and set debug level. for other targets use --debug-level.
 --debug-level=0|1|2                     ; specify debug level for syslog and @<filename>
 --dry-run                               ; verify parameters and exit with code 0 if successful
 --version                                      ; print version and exit
 --bind-addr=<v4_addr>|<v6_addr>         ; for v6 link locals append %interface_name : fe80::1%br-lan
 --bind-iface4=<interface_name>          ; bind to the first ipv4 addr of interface
 --bind-iface6=<interface_name>          ; bind to the first ipv6 addr of interface
 --bind-linklocal=no|unwanted|prefer|force
                                         ; no : bind only to global ipv6
                                         ; unwanted (default) : prefer global address, then LL
                                         ; prefer : prefer LL, then global
                                         ; force : LL only
 --bind-wait-ifup=<sec>                  ; wait for interface to appear and up
 --bind-wait-ip=<sec>                    ; after ifup wait for ip address to appear up to N seconds
 --bind-wait-ip-linklocal=<sec>          ; accept only link locals first N seconds then any
 --bind-wait-only                        ; wait for bind conditions satisfaction then exit. return code 0 if success.
 --connect-bind-addr=<v4_addr>|<v6_addr> ; address for outbound connections. for v6 link locals append %%interface_name
 --port=<port>                           ; port number to listen on
 --socks                                 ; implement socks4/5 proxy instead of transparent proxy
 --local-rcvbuf=<bytes>                  ; SO_RCVBUF for local legs
 --local-sndbuf=<bytes>                  ; SO_SNDBUF for local legs
 --remote-rcvbuf=<bytes>                 ; SO_RCVBUF for remote legs
 --remote-sndbuf=<bytes>                 ; SO_SNDBUF for remote legs
 --nosplice                              ; do not use splice to transfer data between sockets
 --skip-nodelay                          ; do not set TCP_NODELAY for outgoing connections. incompatible with split.
 --local-tcp-user-timeout=<seconds>      ; set tcp user timeout for local leg (default : 10, 0 = system default)
 --remote-tcp-user-timeout=<seconds>     ; set tcp user timeout for remote leg (default : 20, 0 = system default)
 --fix-seg=<int>                         ; recover failed TCP segmentation at the cost of slowdown. wait up to N msec.
 --ipcache-lifetime=<int>                ; time in seconds to keep cached domain name (default 7200). 0 = no expiration
 --ipcache-hostname=[0|1]                ; 1 or no argument enables ip->hostname caching
 --no-resolve                            ; disable socks5 remote dns
 --resolver-threads=<int>                ; number of resolver worker threads
 --maxconn=<max_connections>             ; max number of local legs
 --maxfiles=<max_open_files>             ; max file descriptors (setrlimit). min requirement is (X*connections+16), where X=6 in tcp proxy mode, X=4 in tampering mode.
                                         ; its worth to make a reserve with 1.5 multiplier. by default maxfiles is (X*connections)*1.5+16
 --max-orphan-time=<sec>                 ; if local leg sends something and closes and remote leg is still connecting then cancel connection attempt after N seconds

 --new                                   ; begin new strategy (new profile)
 --skip                                  ; do not use this profile
 --filter-l3=ipv4|ipv6                   ; L3 protocol filter. multiple comma separated values allowed.
 --filter-tcp=[~]port1[-port2]|*         ; TCP port filter. ~ means negation. comma separated list supported.
 --filter-l7=[http|tls|unknown]          ; L6-L7 protocol filter. multiple comma separated values allowed.
 --ipset=<filename>                      ; ipset include filter (one ip/CIDR per line, ipv4 and ipv6 accepted, gzip supported, multiple ipsets allowed)
 --ipset-ip=<ip_list>                    ; comma separated fixed subnet list
 --ipset-exclude=<filename>              ; ipset exclude filter (one ip/CIDR per line, ipv4 and ipv6 accepted, gzip supported, multiple ipsets allowed)
 --ipset-exclude-ip=<ip_list>            ; comma separated fixed subnet list

 --hostlist=<filename>                   ; only act on hosts in the list (one host per line, subdomains auto apply if not prefixed with '^', gzip supported, multiple hostlists allowed)
 --hostlist-domains=<domain_list>        ; comma separated fixed domain list
 --hostlist-exclude=<filename>           ; do not act on hosts in the list (one host per line, subdomains auto apply if not prefixed with '^', gzip supported, multiple hostlists allowed)
 --hostlist-exclude-domains=<domain_list> ; comma separated fixed domain list
 --hostlist-auto=<filename>              ; detect DPI blocks and build hostlist automatically
 --hostlist-auto-fail-threshold=<int>    ; how many failed attempts cause hostname to be added to auto hostlist (default : 3)
 --hostlist-auto-fail-time=<int>         ; all failed attemps must be within these seconds (default : 60)
 --hostlist-auto-debug=<logfile>         ; debug auto hostlist positives

 --split-pos=N|-N|marker+N|marker-N      ; comma separated list of split positions
                                         ; markers: method,host,endhost,sld,endsld,midsld,sniext  
 --split-any-protocol                    ; split not only http and TLS
 --disorder[=http|tls]                   ; when splitting simulate sending second fragment first
 --oob[=http|tls]                        ; when splitting send out of band byte. default is HEX 0x00.
 --oob-data=<char>|0xHEX                 ; override default 0x00 OOB byte.
 --hostcase                              ; change Host: => host:
 --hostspell                             ; exact spelling of "Host" header. must be 4 chars. default is "host"
 --hostdot                               ; add "." after Host: name
 --hosttab                               ; add tab after Host: name
 --hostnospace                           ; remove space after Host:
 --hostpad=<bytes>                       ; add dummy padding headers before Host:
 --domcase                               ; mix domain case after Host: like this : TeSt.cOm
 --methodspace                           ; add extra space after method
 --methodeol                             ; add end-of-line before method
 --unixeol                               ; replace 0D0A to 0A
 --tlsrec=N|-N|marker+N|marker-N         ; make 2 TLS records. split at specified logical part. don't split if SNI is not present.
 --tlsrec-pos=<pos>                      ; make 2 TLS records. split at specified pos
 --mss=<int>                             ; set client MSS. forces server to split messages but significantly decreases speed !
 --tamper-start=[n]<pos>                 ; start tampering only from specified outbound stream position. byte pos or block number ('n'). default is 0.
 --tamper-cutoff=[n]<pos>                ; do not tamper anymore after specified outbound stream position. byte pos or block number ('n'). default is unlimited.
 --daemon                                ; daemonize
 --pidfile=<filename>                    ; write pid to file
 --user=<username>                       ; drop root privs
 --uid=uid[:gid1,gid2,...]               ; drop root privs
```

### TCP segmentation in tpws

**tpws** like **nfqws** supports multiple splits. Split [markers](#tcp-segmentation) are specified in `--split-pos` parameter.

On the socket level there's no guaranteed way to force OS to send pieces of data in separate packets. OS has a send buffer for each socket. If `TCP_NODELAY` socket option is enabled and send buffer is empty OS will likely send data immediately. If send buffer is not empty OS will coalesce it with new data and send in one packet if possible.

In practice outside of massive transmissions it's usually enough to enable `TCP_NODELAY` and use separate `send()` calls to force custom TCP segmentation. But if there're too many split segments Linux can combined some pieces and break desired behaviour. BSD and Windows are more predictable in this case. That's why it's not recommended to use too many splits. Tests revealed that 8+ can become problematic.

Since linux kernel 4.6 **tpws** can recognize TCP segmentation failures and warn about them. `--fix-seg` can fix segmentation failures at the cost of some slowdown. It waits for several msec until all previous data is sent. This breaks async processing model and slows down every other connection going through **tpws**. Thus it's not recommended on highly loaded systems. But can be compromise for home systems.

If you're attempting to split massive transmission with `--split-any-protocol` option it will definitely cause massive segmentation failures. Do not do that without `--tamper-start` and `--tamper-cutoff` limiters.

**tpws** works on socket level and receives in one shot long requests (TLS with kyber) that should normally require several TCP packets. It tampers entire received block without knowing how much packets it will take. OS will do additional segmenation to meet MTU.

`--disorder` sends every odd packet with TTL=1. Server receives even packets fastly. Then client OS retransmits odd packets with normal TTL and server receives them. In case of 6 segments server and DPI will see them in this order : `2 4 6 1 3 5`. This way of disorder causes some delays. Default retransmission timeout in Linux is 200 ms.

`--oob` sends one out-of-band byte in the end of the first split segment.

`--oob` and `--disorder` can be combined only in Linux. Others OS do not handle this correctly.

### TLSREC

`--tlsrec` allow to split TLS ClientHello into 2 TLS records in one TCP segment. It accepts single pos marker.

`--tlsrec` breaks significant number of sites. Crypto libraries on servers usually accept fine modified ClientHello but middleboxes such as CDNs and ddos guards - not always. Use of `--tlsrec` without filters is discouraged.

### MSS

`--mss` sets TCP_MAXSEG socket option. Client sets this value in MSS TCP option in the SYN packet.
Server replies with it's own MSS in SYN,ACK packet. Usually servers lower their packet sizes but they still don't fit to supplied MSS. The greater MSS client sets the bigger server's packets will be.
If it's enough to split TLS 1.2 ServerHello, it may fool DPI that checks certificate domain name.
This scheme may significantly lower speed. Hostlist filter is possible only in socks mode if client uses remote resolving (firefox `network.proxy.socks_remote_dns`) or if `ipcache-hostname` is enabled.
`--mss` is not required for TLS1.3. If TLS1.3 is negotiable then MSS make things only worse. Use only if nothing better is available. Works only in Linux, not BSD or MacOS.

### Other tamper options

`--hostpad=<bytes>` adds padding headers before `Host:` with specified number of bytes. If `<bytes>` is too large headers are split by 2K. Padding more that 64K is not supported and not accepted by http servers.

It's useful against stateful DPI's that reassemble only limited amount of data. Increase padding `<bytes>` until website works. If minimum working `<bytes>` is close to MTU then it's likely DPI is not reassembling packets. Then it's better to use regular split instead of `--hostpad`.

### Supplementary options

**tpws** can bind to multiple interfaces and IP addresses (up to 32).

Port number is always the same.

Parameters `--bind-iface*` and `--bind-addr` create new bind.

Other parameters `--bind-*` are related to the last bind.

link local ipv6 (`fe80::/8`) mode selection :

```
--bind-iface6 --bind-linklocal=no : first selects private address fc00::/7, then global address
--bind-iface6 --bind-linklocal=unwanted : first selects private address fc00::/7, then global address, then LL
--bind-iface6 --bind-linklocal=prefer : first selects LL, then private address fc00::/7, then global address
--bind-iface6 --bind-linklocal=force : select only LL
```

To bind to all ipv4 specify `--bind-addr "0.0.0.0"`, all ipv6 - `::`. 

`--bind-addr=""` - mean bind to all ipv4 and ipv6.

If no binds are specified default bind to all ipv4 and ipv6 addresses is created.

To bind to a specific link local address do : `--bind-iface6=fe80::aaaa:bbbb:cccc:dddd%iface-name`

The `--bind-wait*` parameters can help in situations where you need to get IP from the interface, but it is not there yet, it is not raised
or not configured.

In different systems, ifup events are caught in different ways and do not guarantee that the interface has already received an IP address of a certain type.

In the general case, there is no single mechanism to hang oneself on an event of the type "link local address appeared on the X interface."

To bind to a specific ip when its interface may not be configured yet do : `--bind-addr=192.168.5.3 --bind-wait-ip=20`

It's possible to bind to any nonexistent address in transparent mode but in socks mode address must exist.

In socks proxy mode no additional system privileges are required. Connections to local IPs of the system where **tpws** runs are prohibited.
tpws supports remote dns resolving (curl : `--socks5-hostname`  firefox : `socks_remote_dns=true`) , but does it in blocking mode.

**tpws** uses async sockets for all activities. Domain names are resolved in multi threaded pool.
Resolving does not freeze other connections. But if there're too many requests resolving delays may increase.
Number of resolver threads is choosen automatically proportinally to `--maxconn` and can be overriden using `--resolver-threads`.
To disable hostname resolve use `--no-resolve` option.

### Multiple strategies

**tpws** like **nfqws** supports multiple strategies. They work mostly like with **nfqws** with minimal differences.
`filter-udp` is absent because **tpws** does not support udp. 0-phase desync methods (`--mss`) can work with hostlist in socks modes with remote hostname resolve.
This is the point where you have to plan profiles carefully. If you use `--mss` and hostlist filters, behaviour can be different depending on remote resolve feature enabled or not.
Use `--mss` both in hostlist profile and profile without hostlist.
Use `curl --socks5` and `curl --socks5-hostname` to issue two kinds of proxy queries.
See `--debug` output to test your setup.

### IPTABLES for tpws

Use the following rules to redirect TCP connections to 'tpws' :
```
iptables -t nat -I OUTPUT -o <wan_interface> -p tcp --dport 80 -m owner ! --uid-owner tpws -j DNAT --to 127.0.0.127:988
iptables -t nat -I PREROUTING -i <lan_interface> -p tcp --dport 80 -j DNAT --to 127.0.0.127:988
```

First rule redirects outgoing from the same system traffic, second redirects passthrough traffic.

DNAT to localhost works only in the **OUTPUT** chain and does not work in the **PREROUTING** chain without setting this sysctl :

`sysctl -w net.ipv4.conf.<lan_interface>.route_localnet=1`

It's also possible to use `-j REDIRECT --to-port 988` instead of DNAT but in the latter case transparent proxy must listen on all IP addresses or on a LAN interface address. It's not too good to listen on all IP and it's not trivial to get specific IP in a shell script. `route_localnet` has it's own security impact if not protected by additional rules. You open `127.0.0.0/8` subnet to the net.

This is how to open only single `127.0.0.127` address :
```
iptables -A INPUT ! -i lo -d 127.0.0.127 -j ACCEPT
iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j DROP
```

Owner filter is required to avoid redirection loops. **tpws** must be run with `--user tpws` parameter.

ip6tables work almost the same with minor differences. ipv6 addresses should be enclosed in square brackets :
```
ip6tables -t nat -I OUTPUT -o <wan_interface> -p tcp --dport 80 -m owner ! --uid-owner tpws -j DNAT --to [::1]:988
```

There's no `route_localnet` for ipv6. DNAT to localhost (`::1`) is possible only in **OUTPUT** chain. In **PREROUTING** chain DNAT is possible to any global address or link local address of the interface where packet came from.

### NFTABLES for tpws

Base nftables scheme :
```
IFACE_WAN=wan
IFACE_LAN=br-lan

sysctl -w net.ipv4.conf.$IFACE_LAN.route_localnet=1

nft create table inet ztest

nft create chain inet ztest localnet_protect
nft add rule inet ztest localnet_protect ip daddr 127.0.0.127 return
nft add rule inet ztest localnet_protect ip daddr 127.0.0.0/8 drop
nft create chain inet ztest input "{type filter hook input priority filter - 1;}"
nft add rule inet ztest input iif != "lo" jump localnet_protect

nft create chain inet ztest dnat_output "{type nat hook output priority dstnat;}"
nft add rule inet ztest dnat_output meta skuid != tpws oifname $IFACE_WAN tcp dport { 80, 443 } dnat ip to 127.0.0.127:988
nft create chain inet ztest dnat_pre "{type nat hook prerouting priority dstnat;}"
nft add rule inet ztest dnat_pre meta iifname $IFACE_LAN tcp dport { 80, 443 } dnat ip to 127.0.0.127:988
```

Delete nftable :
```
nft delete table inet ztest
```


## Ways to get a list of blocked IP

nftables can't work with ipsets. Native nf sets require lots of RAM to load large ip lists with subnets and intervals.
In case you're on a low RAM system and need large lists it may be required to fall back to iptables+ipset.

1. Enter the blocked domains to `ipset/zapret-hosts-user.txt` and run `ipset/get_user.sh`
At the output, you get `ipset/zapret-ip-user.txt` with IP addresses.

2. `ipset/get_reestr_*.sh`. Russian specific

3. `ipset/get_antifilter_*.sh`. Russian specific

4. `ipset/get_config.sh`. This script calls what is written into the GETLIST variable from the config file.

If the variable is not defined, then only lists for ipsets nozapret/nozapret6 are resolved.

So, if you're not russian, the only way for you is to manually add blocked domains.
Or write your own `ipset/get_iran_blocklist.sh` , if you know where to download this one.

On routers, it is not recommended to call these scripts more than once in 2 days to minimize flash memory writes.

`ipset/create_ipset.sh` executes forced ipset update.
With `no-update` parameter `create_ipset.sh` creates ipset but populate it only if it was actually created.

It's useful when multiple subsequent calls are possible to avoid wasting of cpu time redoing the same job.

Ipset loading is resource consuming. Its a good idea to call create_ipset without `no-update` parameter

only once a several days. Use it with `no-update` option in other cases.

ipset scripts automatically call ip2net utility.
ip2net helps to reduce ip list size by combining IPs to subnets. Also it cuts invalid IPs from the list.
Stored lists are already processed by ip2net. They are error free and ready for loading.

`create_ipset.sh` supports loading ip lists from gzip files. First it looks for the filename with the ".gz" extension,
such as `zapret-ip.txt.gz`, if not found it falls back to the original name `zapret-ip.txt`.

So your own get_iran_blockslist.sh can use "zz" function to produce gz. Study how other russian `get_XXX.sh` work.

Gzipping helps saving a lot of precious flash space on embedded systems.

User lists are not gzipped because they are not expected to be very large.

You can add a list of domains to `ipset/zapret-hosts-user-ipban.txt`. Their ip addresses will be placed
in a separate ipset "ipban". It can be used to route connections to transparent proxy "redsocks" or VPN.

IPV6: if ipv6 is enabled, then additional txt's are created with the same name, but with a "6" at the end before the extension.

`zapret-ip.txt` => `zapret-ip6.txt`

The ipsets zapret6 and ipban6 are created.

IP EXCLUSION SYSTEM. All scripts resolve `zapret-hosts-user-exclude.txt` file, creating `zapret-ip-exclude.txt` and `zapret-ip-exclude6.txt`.

They are the source for ipsets nozapret/nozapret6. All rules created by init scripts are created with these ipsets in mind.
The IPs placed in them are not involved in the process.
zapret-hosts-user-exclude.txt can contain domains, ipv4 and ipv6 addresses or subnets.

FreeBSD. `ipset/*.sh` scripts also work in FreeBSD. Instead of ipset they create ipfw lookup tables with the same names as in Linux.
ipfw tables can store both ipv4 and ipv6 addresses and subnets. There's no 4 and 6 separation.

LISTS_RELOAD config parameter defines a custom lists reloading command.
Its useful on BSD systems with PF.
LISTS_RELOAD=-  disables reloading ip list backend.

## Domain name filtering

An alternative to ipset is to use **tpws** or **nfqws** with a list(s) of domains.
Both **tpws** and **nfqws** take any number of include (`--hostlist`) and exclude (`--hostlist-exclude`) domain lists.
All lists of the same type are combined internally leaving only 2 lists : include and exclude.

Exclude list is checked first. Fooling is cancelled if domain belongs to exclude list.
If include list is present and domain does not belong to that list fooling is also cancelled.
Empty list means absent list. Otherwise fooling goes on.

Launch system looks for 2 include lists :

`ipset/zapret-hosts-users.txt.gz` or `ipset/zapret-hosts-users.txt`

`ipset/zapret-hosts.txt.gz` or `ipset/zapret-hosts.txt`

and 1 exclude list

`ipset/zapret-hosts-users-exclude.txt.gz` or `ipset/zapret-hosts-users-exclude.txt`

If `MODE_FILTER=hostlist` all present lists are passed to **nfqws** or **tpws**.
If all include lists are empty it works like no include lists exist at all.
If you need "all except" mode you dont have to delete zapret-hosts-users.txt. Just make it empty.

Subdomains auto apply. For example, "ru" in the list affects "*.ru" .
`^` prefix symbol disables subdomain match.

**tpws** and **nfqws** automatically reload lists if their modification time or file size is changed.
HUP signal forcibly reloads all lists.

When filtering by domain name, daemons should run without filtering by ipset.
When using large regulator lists estimate the amount of RAM on the router !

## **autohostlist** mode

This mode analyzes both client requests and server replies.
If a host is not in any list and a situation similar to block occurs host is automatically added to the special list both in memory and file.
Use exclude hostlist to prevent autohostlist triggering.
If it did happen - delete the undesired record from the file.

In case of nfqws it's required to redirect both incoming and outgoing traffic to the queue.
It's strongly recommended to use connbytes filter or nfqws will process gigabytes of incoming traffic.
For the same reason it's not recommended to use autohostlist mode in BSDs. BSDs do not support connbytes or similar mechanism.

**nfqws** и **tpws** detect the folowing situations :
1) [nfqws] Multiple retransmissions of the first request inside a TCP session having host.
2) [nfqws,tpws] RST in response to the first request.
3) [nfqws,tpws] HTTP redirect in response to the first http request with 2nd level domain diferent from the original.
4) [tpws] Client closes connection after first request without having server reply (no reponse from server, timeout).

To minimize false positives there's fail counter. If in specific time occurs more than specified number of fails
the host is added to the list. Then DPI bypass strategy start to apply immediately.

For the user autohostlist mode looks like this.
When for the first time user visits a blocked website it sees block page, connection reset
or browser hangs until timeout, then display a error.
User presses multiple times F5 causing browser to retry attempts.
After some retries a website opens and next time works as expected.

With autohostlist mode it's possible to use bypass strategies that break lots of sites.
If a site does not behave like blocked no fooling applies.
Otherwise it's nothing to lose.

However false positives still can occur in case target website is behaving abnormally
(may be due to DDoS attack or server malfunction). If it happens bypass strategy
may start to break the website. This situation can only be controlled manually.
Remove undesired domain from the autohostlist file.
Use exclude hostlist to prevent further auto additions.

It's possible to use one auto hostlist with multiple processes. All processes check for file modification time.
If a process modified autohostlist, all others will reread it automatically.
All processes must run with the same uid.

If zapret scripts are used then autohostlist is `ipset/zapret-hosts-auto.txt`
and exlude list is `ipset/zapret-hosts-user-exclude.txt`. autohostlist mode
includes hostlist mode. You can use `ipset/zapret-hosts-user.txt`.


## Choosing parameters

The file `/opt/zapret/config` is used by various components of the system and contains basic settings.
It needs to be viewed and edited if necessary.

Which firewall type use on linux systems : `nftables` or `iptables`.
On traditional systems `nftables` is selected by default if `nft` is installed.
On openwrt by default `nftables` is selected on `firewall4` based systems.

`FWTYPE=iptables`

With `nftables` post-NAT scheme is used by default. It allows more DPI attacks on forwarded traffic.
It's possible to use `iptables`-like pre-NAT scheme. **nfqws** will see client source IPs and display them in logs.

`#POSTNAT=0`

There'are 3 standard options configured separately and independently : `tpws-socks`, **tpws**, **nfqws**.
They can be used alone or combined. Custom scripts in `init.d/{sysv,openwrt,macos}/custom.d` are always applied.

`tpws-socks` requires daemon parameter configuration but does not require traffic interception.
Other standard options require also traffic interception.
Each standard option launches single daemon instance. Strategy differiences are managed using multi-profile scheme.
Main rule for interception is "intercept required minumum". Everything else only wastes CPU resources and slows down connection.

`--ipset` option is prohibited intentionally to disallow easy to use but ineffective user-mode filtering.
Use kernel ipsets instead. It may require custom scripts.

To use standard updatable hostlists from the `ipset` dir use `<HOSTLIST>` placeholder. It's automatically replaced
with hostlist parameters if `MODE_FILTER` variable enables hostlists and is removed otherwise.
Standard hostlists are expected in final (fallback) strategies closing groups of filter parameters.
Don't use `<HOSTLIST>` in highly specialized profiles. Use your own filter or hostlist(s).
`<HOSTLIST_NOAUTO>` marker uses standard autohostlist as usual hostlist thus disabling auto additions in this profile.
If any other profile adds something this profile accepts the change automatically.


**tpws** socks proxy mode switch

`TPWS_SOCKS_ENABLE=0`

Listening tcp port for **tpws** proxy mode.

`TPPORT_SOCKS=987`

**tpws** socks mode parameters

```
TPWS_SOCKS_OPT="
--filter-tcp=80 --methodeol <HOSTLIST> --new
--filter-tcp=443 --split-pos=1,midsld --disorder <HOSTLIST>"
"
```

**tpws** transparent mode switch

`TPWS_ENABLE=0`

**tpws** transparent mode target ports

`TPWS_PORTS=80,443`

**tpws** transparent mode parameters

```
TPWS_OPT="
--filter-tcp=80 --methodeol <HOSTLIST> --new
--filter-tcp=443 --split-pos=1,midsld --disorder <HOSTLIST>"
"
```

**nfqws** enable switch

`NFQWS_ENABLE=0`

**nfqws** port targets for `connbytes`-limited interception. `connbytes` allows to intercept only starting packets from connections.
This is more effective kernel-mode alternative to `nfqws --dpi-desync-cutoff=nX`.

```
NFQWS_PORTS_TCP=80,443
NFQWS_PORTS_UDP=443
```

How many starting packets should be intercepted to nfqws in each direction

```
NFQWS_TCP_PKT_OUT=$((6+$AUTOHOSTLIST_RETRANS_THRESHOLD))
NFQWS_TCP_PKT_IN=3
NFQWS_UDP_PKT_OUT=$((6+$AUTOHOSTLIST_RETRANS_THRESHOLD))
NFQWS_UDP_PKT_IN=0
```

There's kind of traffic that requires interception of entire outgoing stream.
Typically it's support for plain http keepalives and stateless DPI.
This mode of interception significantly increases CPU utilization. Use with care and only if required.
Here you specify port numbers for unlimited interception.
It's advised also to remove these ports from `connbytes`-limited interception list.

```
#NFQWS_PORTS_TCP_KEEPALIVE=80
#NFQWS_PORTS_UDP_KEEPALIVE=
```

**nfqws** parameters

```
NFQWS_OPT="
--filter-tcp=80 --dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2 --dpi-desync-fooling=md5sig <HOSTLIST> --new
--filter-tcp=443 --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq,md5sig <HOSTLIST> --new
--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 <HOSTLIST_NOAUTO>
"
```


Host filtering mode :
```
none - apply fooling to all hosts
ipset - limit fooling to hosts from ipset zapret/zapret6
hostlist - limit fooling to hosts from hostlist
autohostlist - hostlist mode + blocks auto detection
```

`MODE_FILTER=none`


flow offloading control (if supported)

```
donttouch : disable system flow offloading setting if selected mode is incompatible with it, dont touch it otherwise and dont configure selective flow offloading
none : always disable system flow offloading setting and dont configure selective flow offloading
software : always disable system flow offloading setting and configure selective software flow offloading
hardware : always disable system flow offloading setting and configure selective hardware flow offloading
```

`FLOWOFFLOAD=donttouch`

The GETLIST parameter tells the install_easy.sh installer which script to call
to update the list of blocked ip or hosts.
Its called via `get_config.sh` from scheduled tasks (crontab or systemd timer).
Put here the name of the script that you will use to update the lists.
If not, then the parameter should be commented out.

You can individually disable ipv4 or ipv6. If the parameter is commented out or not equal to "1",
use of the protocol is permitted.

```
#DISABLE_IPV4=1
DISABLE_IPV6=1
```

The number of threads for mdig multithreaded DNS resolver (1..100).
The more of them, the faster, but will your DNS server be offended by hammering ?

`MDIG_THREADS=30`

temp directory. Used by ipset/*.sh scripts for large lists processing.
/tmp by default. Can be reassigned if /tmp is tmpfs and RAM is low.
TMPDIR=/opt/zapret/tmp

ipset and nfset options :

```
SET_MAXELEM=262144
IPSET_OPT="hashsize 262144 maxelem 2097152
```

Kernel automatically increases hashsize if ipset is too large for the current hashsize.
This procedure requires internal reallocation and may require additional memory.
On low RAM systems it can cause errors.
Do not use too high hashsize. This way you waste your RAM. And dont use too low hashsize to avoid reallocs.

ip2net options. separate for ipv4 and ipv6.

```
IP2NET_OPT4="--prefix-length=22-30 --v4-threshold=3/4"
IP2NET_OPT6="--prefix-length=56-64 --v6-threshold=5"
```

autohostlist mode tuning.

```
AUTOHOSTLIST_RETRANS_THRESHOLD=3
AUTOHOSTLIST_FAIL_THRESHOLD=2
AUTOHOSTLIST_FAIL_TIME=60
AUTOHOSTLIST_DEBUG=0
```

Enable gzip compression for large lists. Used by ipset/*.sh scripts.

`GZIP_LISTS=1`

Command to reload ip/host lists after update.
Comment or leave empty for auto backend selection : ipset or ipfw if present.
On BSD systems with PF no auto reloading happens. You must provide your own command.
Newer FreeBSD versions support table only reloading : `pfctl -Tl -f /etc/pf.conf`
Set to "-" to disable reload.

`LISTS_RELOAD="pfctl -f /etc/pf.conf"`

In openwrt there's default network `lan`. Only traffic coming from this network is redirected to tpws by default.
To override this behaviour set the following variable :

`OPENWRT_LAN="lan lan2 lan3"`

In openwrt wan interfaces are those having default route. Separately for ipv4 and ipv6.
This can be redefined :
```
OPENWRT_WAN4="wan4 vpn"
OPENWRT_WAN6="wan6 vpn6"
```

The `INIT_APPLY_FW=1` parameter enables the init script to independently apply iptables rules.
With other values or if the parameter is commented out, the rules will not be applied.
This is useful if you have a firewall management system, in the settings of which you should tie the rules.
Not applicable to `OpenWRT` if used with `firewall3+iptables`.

`FILTER_TTL_EXPIRED_ICMP=1` blocks icmp time exceeded messages in response to connections handled by nfqws.
Linux closes socket if it receives this icmp in response to SYN packet. Similar mechanism exists for datagram sockets.
It's better to disable this if you do not expect problems caused by icmp.

The following settings are not relevant for openwrt :

If your system works as a router, then you need to enter the names of the internal and external interfaces:
```
IFACE_LAN=eth0
IFACE_WAN=eth1
IFACE_WAN6="henet ipsec0"
```
Multiple interfaces are space separated. IF IFACE_WAN6 is omitted then IFACE_WAN value is taken.

IMPORTANT: configuring routing, masquerade, etc. not a zapret task.
Only modes that intercept transit traffic are enabled.
It's possible to specify multiple interfaces like this : `IFACE_LAN="eth0 eth1 eth2"`


## Screwing to the firewall control system or your launch system

If you use some kind of firewall management system, then it may conflict with an existing startup script.
When re-applying the rules, it could break the iptables settings from the zapret.
In this case, the rules for iptables should be screwed to your firewall separately from running tpws or nfqws.

The following calls allow you to apply or remove iptables rules separately:

```
 /opt/zapret/init.d/sysv/zapret start_fw
 /opt/zapret/init.d/sysv/zapret stop_fw
 /opt/zapret/init.d/sysv/zapret restart_fw
```

And you can start or stop the demons separately from the firewall:

```
 /opt/zapret/init.d/sysv/zapret start_daemons
 /opt/zapret/init.d/sysv/zapret stop_daemons
 /opt/zapret/init.d/sysv/zapret restart_daemons
```

nftables nearly eliminate conflicts betweeen firewall control systems because they allow
separate tables and netfilter hooks. `zapret` nf table is used for zapret purposes.
If your system does not touch it everything will likely be OK.

Some additional nftables-only calls exist :

Lookup `lanif`, `wanif`, `wanif6` and `flow table` interface sets.
```
 /opt/zapret/init.d/sysv/zapret list_ifsets
```

Renew `lanif`, `wanif`, `wanif6` and `flow table` interface sets.
Taken from `IFACE_LAN`, `IFACE_WAN` config variables on traditional Linux systems.
Autoselected on `OpenWRT`. `lanif` can be extended using `OPENWRT_LAN` config variable.
```
 /opt/zapret/init.d/sysv/zapret reload_ifsets
```

Calls `nft -t list table inet zapret`.
```
 /opt/zapret/init.d/sysv/zapret list_table
```

It's also possible to hook with your script to any stage of zapret firewall processing.
The following settings are available in the zapret config file :

```
INIT_FW_PRE_UP_HOOK="/etc/firewall.zapret.hook.pre_up"
INIT_FW_POST_UP_HOOK="/etc/firewall.zapret.hook.post_up"
INIT_FW_PRE_DOWN_HOOK="/etc/firewall.zapret.hook.pre_down"
INIT_FW_POST_DOWN_HOOK="/etc/firewall.zapret.hook.post_down"
```

Hooks are extremely useful if you need nftables sets populated by zapret scripts.
nfsets can only belong to one table. You have to write rule there and synchorize them with zapret scripts.

## Installation

### Checking ISP

Before running zapret you must discover working bypass strategy.
`blockcheck.sh` automates this process. It first checks DNS then tries many strategies finding the working ones.
Note that DNS check is mostly Russia targeted. It checks several pre-defined blocked in Russia domains and
verifies system DNS answers with public DNS answers. Because ISP can block public DNS or redirect any DNS queries
to their servers `blockcheck.sh` also checks that all returned answers are unique. Usually if DNS is blocked
ISP returns single ip for all blocked domains to redirect you to their "access denied" page.
DoH servers are used automatically for checks if DNS spoof is detected.
`blockcheck.sh` works on all systems supported by `zapret`.

### desktop linux system

Simple install works on most modern linux distributions with systemd or openrc, OpenWRT and MacOS.
Run `install_easy.sh` and answer its questions.

### OpenWRT

`install_easy.sh` works on openwrt but there're additional challenges.
They are mainly about possibly low flash free space.
Simple install will not work if it has no space to install itself and required packages from the repo.

Another challenge would be to bring zapret to the router. You can download zip from github and use it.
Install openssh-sftp-server and unzip to openwrt and use sftp to transfer the file.
It's also not too hard to use 'nc' (netcat) for file transfer.

The best way to start is to put zapret dir to `/tmp` and run `/tmp/zapret/install_easy.sh` from there.
After installation remove `/tmp/zapret` to free RAM.

The absolute minimum for openwrt is 64/8 system, 64/16 is comfortable, 128/extroot is recommended.

For low storage openwrt see `init.d/openwrt-minimal`.

### Android

Its not possible to use **nfqws** and **tpws** in transparent proxy mode without root privileges. Without root **tpws** can run in `--socks` mode.

Android has NFQUEUE and **nfqws** should work.

There's no `ipset` support unless you run custom kernel. In common case task of bringing up `ipset` on android is ranging from "not easy" to "almost impossible", unless you find working kernel image for your device.

Although linux binaries work it's recommended to use Android specific ones. They have no problems with user names, local time, DNS, ...
Its recommended to use gid 3003 (AID_INET), otherwise **tpws** will not have inet access.

Example : `--uid 1:3003`

In iptables use : `! --uid-owner 1` instead of `! --uid-owner tpws`.

**nfqws** should be executed with `--uid 1`. Otherwise on some devices or firmwares kernel may partially hang. Looks like processes with certain uids can be suspended. With buggy chineese cellular interface driver this can lead to device hang.

Write your own shell script with iptables and **tpws**, run it using your root manager.
Autorun scripts are here :

magisk  : `/data/adb/service.d`

supersu : `/system/su.d`

How to run **tpws** on root-less android.
You can't write to `/system`, `/data`, can't run from sd card.
Selinux prevents running executables in `/data/local/tmp` from apps.
Use adb and adb shell.

```
mkdir /data/local/tmp/zapret
adb push tpws /data/local/tmp/zapret
chmod 755 /data/local/tmp/zapret /data/local/tmp/zapret/tpws
chcon u:object_r:system_file:s0 /data/local/tmp/zapret/tpws
```

Now its possible to run `/data/local/tmp/zapret/tpws` from any app such as tasker.

### FreeBSD, OpenBSD, MacOS

see [BSD documentation](./bsd.en.md)

### Windows (WSL)

see [Windows documentation](./windows.en.md)

### Other devices

Author's goal does not include easy supporting as much devices as possibles.
Please do not ask for easy supporting firmwares. It requires a lot of work and owning lots of devices. Its counterproductive.
As a devices owner its easier for you and should not be too hard if firmware is open.
Most closed stock firmwares are not designed for custom usage and sometimes actively prevent it.
In the latter case you have to hack into it and reverse engineer. Its not easy.
Binaries are universal. They can run on almost all firmwares.
You will need :
 * root shell access. true sh shell, not microtik-like console
 * startup hook
 * r/w partition to store binaries and startup script with executable permission (+x)
 * **tpws** can be run almost anywhere but **nfqws** require kernel support for NFQUEUE. Its missing in most firmwares.
 * too old 2.6 kernels are unsupported and can cause errors. newer 2.6 kernels are OK.
If binaries crash with segfault (rare but happens on some kernels) try to unpack upx like this : upx -d tpws.

First manually debug your scenario. Run iptables + daemon and check if its what you want.
Write your own script with iptables magic and run required daemon from there. Put it to startup.
Dont ask me how to do it. Its different for all firmwares and requires studying.
Find manual or reverse engineer yourself.
Check for race conditions. Firmware can clear or modify iptables after your startup script.
If this is the case then run another script in background and add some delay there.

## Donations

Are welcome here :

USDT `0x3d52Ce15B7Be734c53fc9526ECbAB8267b63d66E`

BTC  `bc1qhqew3mrvp47uk2vevt5sctp7p2x9m7m5kkchve`

ETH  `0x3d52Ce15B7Be734c53fc9526ECbAB8267b63d66E`
