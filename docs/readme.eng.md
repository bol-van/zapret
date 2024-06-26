## What is it for

A stand-alone (without 3rd party servers) DPI circumvention tool.
May allow to bypass http(s) website blocking or speed shaping, resist signature tcp/udp protocol discovery.

The project is mainly aimed at the Russian audience to fight russian regulator named "Roskomnadzor".
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

For options 2 and 3, tpws and nfqws programs are implemented, respectively.
You need to run them with the necessary parameters and redirect certain traffic with iptables or nftables.

To redirect a TCP connection to a transparent proxy, the following commands are used:

forwarded traffic :
`iptables -t nat -I PREROUTING -i <internal_interface> -p tcp --dport 80 -j DNAT --to 127.0.0.127:988`

outgoing traffic :
`iptables -t nat -I OUTPUT -o <external_interface> -p tcp --dport 80 -m owner ! --uid-owner tpws -j DNAT --to 127.0.0.127:988`

DNAT on localhost works in the OUTPUT chain, but does not work in the PREROUTING chain without enabling the route_localnet parameter:

`sysctl -w net.ipv4.conf.<internal_interface>.route_localnet=1`

You can use `-j REDIRECT --to-port 988` instead of DNAT, but in this case the transparent proxy process 
should listen on the ip address of the incoming interface or on all addresses. Listen all - not good
in terms of security. Listening one (local) is possible, but automated scripts will have to recognize it,
then dynamically enter it into the command. In any case, additional efforts are required.
Using route_localnet can also introduce some security risks. You make available from internal_interface everything
bound to `127.0.0.0/8`. Services are usually bound to `127.0.0.1`. Its possible to deny input to `127.0.0.1` from all interfaces except lo
or bind tpws to any other IP from `127.0.0.0/8` range, for example to `127.0.0.127`, and allow incomings only to that IP :

```
iptables -A INPUT ! -i lo -d 127.0.0.127 -j ACCEPT
iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j DROP
```

Owner filter is necessary to prevent recursive redirection of connections from tpws itself.
tpws must be started under OS user `tpws`.

NFQUEUE redirection of the outgoing traffic and forwarded traffic going towards the external interface,
can be done with the following commands:

`iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp --dport 80 -j NFQUEUE --queue-num 200 --queue-bypass`

In order not to touch the traffic to unblocked addresses, you can take a list of blocked hosts, resolve it
into IP addresses and put them to ipset 'zapret', then add a filter to the command:

`iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp --dport 80 -m set --match-set zapret dst -j NFQUEUE --queue-num 200 --queue-bypass`

Some DPIs catch only the first http request, ignoring subsequent requests in a keep-alive session.
Then we can reduce CPU load, refusing to process unnecessary packets.

`iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp --dport 80 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:6 -m mark ! --mark 0x40000000/0x40000000 -m set --match-set zapret dst -j NFQUEUE --queue-num 200 --queue-bypass`

Mark filter does not allow nfqws-generated packets to enter the queue again.
Its necessary to use this filter when also using `connbytes 1:6`. Without it packet ordering can be changed breaking the whole idea.

Some attacks require redirection of incoming packets :

`iptables -t mangle -I PREROUTING -i <external_interface> -p tcp --sport 80 -m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:6 -m set --match-set zapret src -j NFQUEUE --queue-num 200 --queue-bypass`

Incoming packets are filtered by incoming interface, source port and IP. This is opposite to the direct rule.

Some techniques that break NAT are possible only with nftables.


## ip6tables

ip6tables work almost exactly the same way as ipv4, but there are a number of important nuances.
In DNAT, you should take the address --to in square brackets. For example :

 `ip6tables -t nat -I OUTPUT -o <external_interface> -p tcp --dport 80 -m owner ! --uid-owner tpws -j DNAT --to [::1]:988`

The route_localnet parameter does not exist for ipv6.
DNAT to localhost (:: 1) is possible only in the OUTPUT chain.
In the PREROUTING DNAT chain, it is possible to any global address or to the link local address of the same interface
the packet came from.
NFQUEUE works without changes.


## nftables

nftables are fine except one very big problem.
nft requires tons of RAM to load large nf sets (ip lists) with subnets/intervals. Most of the home routers can't afford that.
For example, even a 256 Mb system can't load a 100K ip list. nft process will OOM.
nf sets do not support overlapping intervals and that's why nft process applies very RAM consuming algorithm to merge intervals so they don't overlap.
There're equivalents to iptables for all other functions. Interface and protocol anonymous sets allow not to write multiple similar rules.
Flow offloading is built-in into new linux kernels and nft versions.

nft version `1.0.2` or higher is recommended. But the higher is version the better.

Some techniques can be fully used only with nftables. It's not possible to queue packets after NAT in iptables.
This limits techniques that break NAT.


## When it will not work

* If DNS server returns false responses. ISP can return false IP addresses or not return anything
when blocked domains are queried. If this is the case change DNS to public ones, such as 8.8.8.8 or 1.1.1.1.Sometimes ISP hijacks queries to any DNS server. Dnscrypt or dns-over-tls help.
* If blocking is done by IP.
* If a connection passes through a filter capable of reconstructing a TCP connection, and which
follows all standards. For example, we are routed to squid. Connection goes through the full OS tcpip stack, fragmentation disappears immediately as a means of circumvention. Squid is correct, it will find everything as it should, it is useless to deceive him. BUT. Only small providers can afford using squid, since it is very resource intensive. Large companies usually use DPI, which is designed for much greater bandwidth.

## nfqws

This program is a packet modifier and a NFQUEUE queue handler.
For BSD systems there is dvtws. Its built from the same source and has almost the same parameters (see bsd.eng.md).
nfqws takes the following parameters:

```
 --debug=0|1
 --qnum=<nfqueue_number>
 --daemon                                       ; daemonize
 --pidfile=<filename>                           ; write pid to file
 --user=<username>                              ; drop root privs
 --uid=uid[:gid]                                ; drop root privs
 --bind-fix4                                    ; apply outgoing interface selection fix for generated ipv4 packets
 --bind-fix6                                    ; apply outgoing interface selection fix for generated ipv6 packets
 --wsize=<window_size>[:<scale_factor>]         ; set window size. 0 = do not modify. OBSOLETE !
 --wssize=<window_size>[:<scale_factor>]        ; set window size for server. 0 = do not modify. default scale_factor = 0.
 --wssize-cutoff=[n|d|s]N                       ; apply server wsize only to packet numbers (n, default), data packet numbers (d), relative sequence (s) less than N
 --ctrack-timeouts=S:E:F[:U]                    ; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default 60:300:60:60
 --hostcase                                     ; change Host: => host:
 --hostspell                                    ; exact spelling of "Host" header. must be 4 chars. default is "host"
 --hostnospace                                  ; remove space after Host: and add it to User-Agent: to preserve packet size
 --domcase                                      ; mix domain case : Host: TeSt.cOm
 --dpi-desync=[<mode0>,]<mode>[,<mode2>]        ; try to desync dpi state. modes : synack fake fakeknown rst rstack hopbyhop destopt ipfrag1 disorder disorder2 split split2 ipfrag2 udplen tamper
 --dpi-desync-fwmark=<int|0xHEX>                ; override fwmark for desync packet. default = 0x40000000 (1073741824)
 --dpi-desync-ttl=<int>                         ; set ttl for desync packet
 --dpi-desync-ttl6=<int>                        ; set ipv6 hop limit for desync packet. by default ttl value is used.
 --dpi-desync-autottl=[<delta>[:<min>[-<max>]]] ; auto ttl mode for both ipv4 and ipv6. default: 1:3-20
 --dpi-desync-autottl6=[<delta>[:<min>[-<max>]]] ; overrides --dpi-desync-autottl for ipv6 only
 --dpi-desync-fooling=<mode>[,<mode>]           ; can use multiple comma separated values. modes : none md5sig ts badseq badsum datanoack hopbyhop hopbyhop2
 --dpi-desync-repeats=<N>                       ; send every desync packet N times
 --dpi-desync-skip-nosni=0|1                    ; 1(default)=do not act on ClientHello without SNI (ESNI ?)
 --dpi-desync-split-pos=<1..9216>               ; data payload split position
 --dpi-desync-split-http-req=method|host        ; split at specified logical part of plain http request
 --dpi-desync-split-tls=sni|sniext              ; split at specified logical part of TLS ClientHello
 --dpi-desync-split-seqovl=<int>                ; use sequence overlap before first sent original split segment
 --dpi-desync-split-seqovl-pattern=<filename>|0xHEX ; pattern for the fake part of overlap
 --dpi-desync-ipfrag-pos-tcp=<8..9216>          ; ip frag position starting from the transport header. multiple of 8, default 8.
 --dpi-desync-ipfrag-pos-udp=<8..9216>          ; ip frag position starting from the transport header. multiple of 8, default 32.
 --dpi-desync-badseq-increment=<int|0xHEX>      ; badseq fooling seq signed increment. default -10000
 --dpi-desync-badack-increment=<int|0xHEX>      ; badseq fooling ackseq signed increment. default -66000
 --dpi-desync-any-protocol=0|1                  ; 0(default)=desync only http and tls  1=desync any nonempty data packet
 --dpi-desync-fake-http=<filename>|0xHEX        ; file containing fake http request
 --dpi-desync-fake-tls=<filename>|0xHEX         ; file containing fake TLS ClientHello (for https)
 --dpi-desync-fake-unknown=<filename>|0xHEX     ; file containing unknown protocol fake payload
 --dpi-desync-fake-syndata=<filename>|0xHEX     ; file containing SYN data payload
 --dpi-desync-fake-quic=<filename>|0xHEX        ; file containing fake QUIC Initial
 --dpi-desync-fake-wireguard=<filename>|0xHEX   ; file containing fake wireguard handshake initiation
 --dpi-desync-fake-dht=<filename>|0xHEX         ; file containing fake DHT (d1..e)
 --dpi-desync-fake-unknown-udp=<filename>|0xHEX ; file containing unknown udp protocol fake payload
 --dpi-desync-udplen-increment=<int>            ; increase or decrease udp packet length by N bytes (default 2). negative values decrease length.
 --dpi-desync-udplen-pattern=<filename>|0xHEX   ; udp tail fill pattern
 --dpi-desync-start=[n|d|s]N                    ; apply dpi desync only to packet numbers (n, default), data packet numbers (d), relative sequence (s) greater or equal than N
 --dpi-desync-cutoff=[n|d|s]N                   ; apply dpi desync only to packet numbers (n, default), data packet numbers (d), relative sequence (s) less than N
 --hostlist=<filename>                          ; apply dpi desync only to the listed hosts (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)
 --hostlist-exclude=<filename>                  ; do not apply dpi desync to the listed hosts (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)
 --hostlist-auto=<filename>                     ; detect DPI blocks and build hostlist automatically
 --hostlist-auto-fail-threshold=<int>           ; how many failed attempts cause hostname to be added to auto hostlist (default : 3)
 --hostlist-auto-fail-time=<int>                ; all failed attemps must be within these seconds (default : 60)
 --hostlist-auto-retrans-threshold=<int>        ; how many request retransmissions cause attempt to fail (default : 3)
 --hostlist-auto-debug=<logfile>        	; debug auto hostlist positives
```

The manipulation parameters can be combined in any way.

WARNING. `--wsize` parameter is now not used anymore in scripts. TCP split can be achieved using DPI desync attack.

### DPI desync attack

After completion of the tcp 3-way handshake, the first data packet from the client goes.
It usually has `GET / ...` or TLS ClientHello. We drop this packet, replacing with something else.
It can be a fake version with another harmless but valid http or https request (`fake`), tcp reset packet (`rst`,`rstack`),
split into 2 segments original packet with fake segment in the middle (`split`).
`fakeknown` sends fake only in response to known application protocol.
In articles these attack have names **TCB desynchronization** and **TCB teardown**.
Fake packet must reach DPI, but do not reach the destination server.
The following means are available: set a low TTL, send a packet with bad checksum,
add tcp option **MD5 signature**. All of them have their own disadvantages :

* md5sig does not work on all servers
* badsum doesn't work if your device is behind NAT which does not pass invalid packets.
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
* badseq packets will be dropped by server, but DPI also can ignore them.
  default badseq increment is set to -10000 because some DPIs drop packets outside of the small tcp window.
  But this also can cause troubles when `--dpi-desync-any-protocol` is enabled.
  To be 100% sure fake packet cannot fit to server tcp window consider setting badseq increment to 0x80000000
* TTL looks like the best option, but it requires special tuning for each ISP. If DPI is further than local ISP websites
  you can cut access to them. Manual IP exclude list is required. Its possible to use md5sig with ttl.
  This way you cant hurt anything, but good chances it will help to open local ISP websites.
  If automatic solution cannot be found then use `zapret-hosts-user-exclude.txt`.
  Some router stock firmwares fix outgoing TTL. Without switching this option off TTL fooling will not work.
* `hopbyhop` is ipv6 only. This fooling adds empty extension header `hop-by-hop options` or two headers in case of `hopbyhop2`.
  Packets with two hop-by-hop headers violate RFC and discarded by all operating systems.
  All OS accept packets with one hop-by-hop header.
  Some ISPs/operators drop ipv6 packets with hop-by-hop options. Fakes will not be processed by the server either because
  ISP drops them or because there are two same headers.
  DPIs may still anaylize packets with one or two hop-by-hop headers.
* `datanoack` sends tcp fakes without ACK flag. Servers do not accept this but DPI may accept.
  This mode may break NAT and may not work with iptables if masquerade is used, even from the router itself.
  Works with nftables properly. Likely requires external IP address (some ISPs pass these packets through their NAT).
* `autottl` tries to automatically guess TTL value that allows DPI to receive fakes and does not allow them to reach the server.
  This tech relies on well known TTL values used by OS : 64,128,255. nfqws takes first incoming packet (YES, you need to redirect it too),
  guesses path length and decreases by `delta` value (default 1). If resulting value is outside the range (min,max - default 3,20)
  then its normalized to min or max. If the path shorter than the value then autottl fails and falls back to the fixed value.
  This can help if multiple DPIs exists on backbone channels, not just near the ISP.
  Can fail if inbound and outbound paths are not symmetric.


`--dpi-desync-fooling` takes multiple comma separated values.

For fake,rst,rstack modes original packet is sent after the fake.

Disorder mode splits original packet and sends packets in the following order :
1. 2nd segment
2. fake 1st segment, data filled with zeroes
3. 1st segment
4. fake 1st segment, data filled with zeroes (2nd copy)

Original packet is always dropped. `--dpi-desync-split-pos` sets split position (default 2).
If position is higher than packet length, pos=1 is used.
This sequence is designed to make reconstruction of critical message as difficult as possible.
Fake segments may not be required to bypass some DPIs, but can potentially help if more sophisticated reconstruction
algorithms are used.
Mode `disorder2` disables sending of fake segments.

Split mode is very similar to disorder but without segment reordering :

1. fake 1st segment, data filled with zeroes
2. 1st segment
3. fake 1st segment, data filled with zeroes (2nd copy)
4. 2nd segment

Mode `split2` disables sending of fake segments. It can be used as a faster alternative to --wsize.

In `disorder2` and 'split2` modes no fake packets are sent, so ttl and fooling options are not required.

`seqovl` adds to the first sent original segment (1st for split, 2nd for disorder) seqovl bytes to the beginning and decreases
sequence number.
In `split2` mode this creates partially in-window packet. OS receives only in-window part.
In `disorder2` mode OS receives fake and real part of the second segment but does not pass received data to the socket until first
segment is received. First segment overwrites fake part of the second segment. Then OS passes original data to the socket.
All unix OS except Solaris preserve last received data. This is not the case for Windows servers and `disorder` with `seqovl` will not work.
Disorder requires `seqovl` to be less than `split_pos`. Either statically defined or automatically calculated.
Otherwise desync is not possible and will not happen.
Method allows to avoid separate fakes. Fakes and real data are mixed.

`hopbyhop`, `destopt` and `ipfrag1` desync modes (they're not the same as `hopbyhop` fooling !) are ipv6 only. One `hop-by-hop`,
`destination options` or `fragment` header is added to all desynced packets.
Extra header increases packet size and can't be applied to the maximum size packets.
If it's not possible to send modified packet original one will be sent.
The idea here is that DPI sees 0 in the next header field of the main ipv6 header and does not
walk through the extension header chain until transport header is found.
`hopbyhop`, `destopt`, `ipfrag1` modes can be used with any second phase mode except `ipfrag1+ipfrag2`.
For example, `hopbyhop,split2` means split original tcp packet into 2 pieces and add hop-by-hop header to both.
With `hopbyhop,ipfrag2` header sequence will be : `ipv6,hop-by-hop,fragment,tcp/udp`.
`ipfrag1` mode may not always work without special preparations. See "IP Fragmentation" notices.

There are DPIs that analyze responses from the server, particularly the certificate from the ServerHello
that contain domain name(s). The ClientHello delivery confirmation is an ACK packet from the server
with ACK sequence number corresponding to the length of the ClientHello+1.
In the disorder variant, a selective acknowledgement (SACK) usually arrives first, then a full ACK.
If, instead of ACK or SACK, there is an RST packet with minimal delay, DPI cuts you off at the request stage.
If the RST is after a full ACK after a delay of about ping to the server, then probably DPI acts
on the server response. The DPI may be satisfied with good ClientHello and stop monitoring the TCP session
without checking ServerHello. Then you were lucky. 'fake' option could work.
If it does not stop monitoring and persistently checks the ServerHello, --wssize parameter may help (see CONNTRACK).
Otherwise it is hardly possible to overcome this without the help of the server.
The best solution is to enable TLS 1.3 support on the server. TLS 1.3 sends the server certificate in encrypted form.
This is recommendation to all admins of blocked sites. Enable TLS 1.3. You will give more opportunities to overcome DPI.

Hosts are extracted from plain http request Host: header and SNI of ClientHello TLS message.
Subdomains are applied automatically. gzip lists are supported.

iptables for performing the attack on the first packet :

`iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:6 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass`

This is good if DPI does not track all requests in http keep-alive session.
If it does, then pass all outgoing packets for http and only first data packet for https :

```
iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:6 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
```

mark is needed to keep away generated packets from NFQUEUE. nfqws sets fwmark when it sends generated packets.
nfqws can internally filter marked packets. but when connbytes filter is used without mark filter
packet ordering can be changed breaking the whole idea of desync attack.

### DPI desync combos

dpi-desync parameter takes up to 3 comma separated arguments.
zero phase means tcp connection establishement (before sending data payload). Mode can be `synack`.
Hostlist filter is not applicable to the zero phase.
Next phases work on packets with data payload.
1st phase mode can be `fake`,`rst`,`rstack`, 2nd phase mode - `disorder`,`disorder2`,`split`,`split2`,`ipfrag2`.
Can be useful for ISPs with more than one DPI.

### SYNACK mode

In geneva docs it's called **TCP turnaround**. Attempt to make the DPI believe the roles of client and server are reversed.

!!! This mode breaks NAT operation and can be used only if there's no NAT between the attacker's device and the DPI !

In linux it's required to remove standard firewall rule dropping INVALID packets in the OUTPUT chain,
for example : `-A OUTPUT -m state --state INVALID -j DROP`

In openwrt it's possible to disable the rule for both FORWARD and OUTPUT chains in /etc/config/firewall :
```
config zone
	option name 'wan'
	.........
	option masq_allow_invalid '1'
```
Unfortunately there's no OUTPUT only switch. It's not desired to remove the rule from the FORWARD chain.
Add the following lines to `/etc/firewall.user` :

```
iptables -D zone_wan_output -m comment --comment '!fw3' -j zone_wan_dest_ACCEPT
ip6tables -D zone_wan_output -m comment --comment '!fw3' -j zone_wan_dest_ACCEPT
```

then `/etc/init.d/firewall restart`

Otherwise raw sending SYN,ACK frame will cause error stopping the further processing.
If you realize you don't need the synack mode it's highly suggested to restore drop INVALID rule.

### SYNDATA mode

Normally SYNs come without data payload. If it's present it's ignored by all major OS if TCP fast open (TFO) is not involved, but may not be ignored by DPI.
Original connections with TFO are not touched because otherwise they would be definitely broken.
Without extra parameter payload is 16 zero bytes.

### Virtual Machines

Most of nfqws packet magic does not work from VMs powered by virtualbox and vmware when network is NATed.
Hypervisor forcibly changes ttl and does not forward fake packets.
Set up bridge networking.

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

Hostlist filter does not affect `--wssize` because it works since the connection initiation when it's not yet possible
to extract the host name.

`--wssize` may slow down sites and/or increase response time. It's desired to use another methods if possible.

`--dpi-desync-cutoff` allows you to set the threshold at which it stops applying dpi-desync.
Can be prefixed with 'n', 'd', 's' symbol the same way as `--wssize-cutoff`.
Useful with `--dpi-desync-any-protocol=1`.
If the connection falls out of the conntrack and --dpi-desync-cutoff is set, dpi desync will not be applied.

Set conntrack timeouts appropriately.

### Reassemble

nfqws supports reassemble of TLS and QUIC ClientHello.
They can consist of multiple packets if kyber crypto is used (default starting from chromium 124).
Chromium randomizes TLS fingerprint. SNI can be in any packet or in-between.
Stateful DPIs usually reassemble all packets in the request then apply block decision.
If nfqws receives a partial ClientHello it begins reassemble session. Packets are delayed until it's finished.
Then they go through desync using fully reassembled message.
On any error reassemble is cancelled and all delayed packets are sent immediately without desync.

There is special support for all tcp split options for multi segment TLS. Split position is treated
as message-oriented, not packet oriented. For example, if your client sends TLS ClientHello with size 2000
and SNI is at 1700, desync mode is fake,split2, then fake is sent first, then original first segment
and the last splitted segment. 3 segments total.


### UDP support

UDP attacks are limited. Its not possible to fragment UDP on transport level, only on network (ip) level.
Only desync modes `fake`,`hopbyhop`,`destopt`,`ipfrag1` and `ipfrag2` are applicable.
`fake`,`hopbyhop`,`destopt` can be used in combo with `ipfrag2`.
`fake` can be used in combo with `udplen` and `tamper`.

`udplen` increases udp payload size by `--dpi-desync-udplen-increment` bytes. Padding is filled with zeroes by default but can be overriden with a pattern.
This option can resist DPIs that track outgoing UDP packet sizes.
Requires that application protocol does not depend on udp payload size.

QUIC initial packets are recognized. Decryption and hostname extraction is supported so `--hostlist` parameter will work.
Wireguard handshake initiation and DHT packets are also recognized.
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


## tpws

tpws is transparent proxy.

```
 --debug=0|1|2			; 0(default)=silent 1=verbose 2=debug
 --bind-addr=<v4_addr>|<v6_addr>; for v6 link locals append %interface_name : fe80::1%br-lan
 --bind-iface4=<interface_name> ; bind to the first ipv4 addr of interface
 --bind-iface6=<interface_name> ; bind to the first ipv6 addr of interface
 --bind-linklocal=no|unwanted|prefer|force
				; no : bind only to global ipv6
 				; unwanted (default) : prefer global address, then LL
				; prefer : prefer LL, then global
				; force : LL only
 --bind-wait-ifup=<sec>         ; wait for interface to appear and up
 --bind-wait-ip=<sec>           ; after ifup wait for ip address to appear up to N seconds
 --bind-wait-ip-linklocal=<sec> ; accept only link locals first N seconds then any
 --bind-wait-only		; wait for bind conditions satisfaction then exit. return code 0 if success.
 --port=<port>			; port number to listen on
 --socks			; implement socks4/5 proxy instead of transparent proxy
 --local-rcvbuf=<bytes>		; SO_RCVBUF for local legs
 --local-sndbuf=<bytes>		; SO_SNDBUF for local legs
 --remote-rcvbuf=<bytes>        ; SO_RCVBUF for remote legs
 --remote-sndbuf=<bytes>	; SO_SNDBUF for remote legs
 --nosplice                     ; do not use splice to transfer data between sockets
 --skip-nodelay			; do not set TCP_NODELAY for outgoing connections. incompatible with split.
 --no-resolve			; disable socks5 remote dns
 --resolver-threads=<int>       ; number of resolver worker threads
 --maxconn=<max_connections>	; max number of local legs
 --maxfiles=<max_open_files>    ; max file descriptors (setrlimit). min requirement is (X*connections+16), where X=6 in tcp proxy mode, X=4 in tampering mode.
				; its worth to make a reserve with 1.5 multiplier. by default maxfiles is (X*connections)*1.5+16
 --max-orphan-time=<sec>	; if local leg sends something and closes and remote leg is still connecting then cancel connection attempt after N seconds

 --hostlist=<filename>          ; only act on hosts in the list (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)
 --hostlist-exclude=<filename>  ; do not act on hosts in the list (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)
 --hostlist-auto=<filename>            ; detect DPI blocks and build hostlist automatically
 --hostlist-auto-fail-threshold=<int>  ; how many failed attempts cause hostname to be added to auto hostlist (default : 3)
 --hostlist-auto-fail-time=<int>       ; all failed attemps must be within these seconds (default : 60)
 --hostlist-auto-debug=<logfile>       	; debug auto hostlist positives

 --split-http-req=method|host	; split http request at specified logical position.
 --split-tls=sni|sniext         ; split at specified logical part of TLS ClientHello
 --split-pos=<numeric_offset>   ; split at specified pos. split-http-req takes precedence over split-pos for http reqs.
 --split-any-protocol		; split not only http and https
 --disorder[=http|tls]          ; when splitting simulate sending second fragment first
 --oob[=http|tls]               ; when splitting send out of band byte. default is HEX 0x00.
 --oob-data=<char>|0xHEX        ; override default 0x00 OOB byte.
 --hostcase                     ; change Host: => host:
 --hostspell                    ; exact spelling of "Host" header. must be 4 chars. default is "host"
 --hostdot                      ; add "." after Host: name
 --hosttab                      ; add tab after Host: name
 --hostnospace                  ; remove space after Host:
 --hostpad=<bytes>		; add dummy padding headers before Host:
 --domcase			; mix domain case after Host: like this : TeSt.cOm
 --methodspace                  ; add extra space after method
 --methodeol                    ; add end-of-line before method
 --unixeol                      ; replace 0D0A to 0A
 --tlsrec=sni|sniext            ; make 2 TLS records. split at specified logical part. don't split if SNI is not present.
 --tlsrec-pos=<pos>             ; make 2 TLS records. split at specified pos
 --mss=<int>                    ; set client MSS. forces server to split messages but significantly decreases speed !
 --mss-pf=[~]port1[-port2]      ; MSS port filter. ~ means negation
 --tamper-start=[n]<pos>        ; start tampering only from specified outbound stream position. byte pos or block number ('n'). default is 0.
 --tamper-cutoff=[n]<pos>       ; do not tamper anymore after specified outbound stream position. byte pos or block number ('n'). default is unlimited.
 --daemon                       ; daemonize
 --pidfile=<filename>           ; write pid to file
 --user=<username>              ; drop root privs
 --uid=uid[:gid]		; drop root privs
```

The manipulation parameters can be combined in any way.

`split-http-req` takes precedence over split-pos for http reqs.

split-pos works by default only on http and TLS ClientHello. use `--split-any-protocol` to act on any packet

tpws can bind to multiple interfaces and IP addresses (up to 32).

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

In socks proxy mode no additional system privileges are required. Connections to local IPs of the system where tpws runs are prohibited.
tpws supports remote dns resolving (curl : `--socks5-hostname`  firefox : `socks_remote_dns=true`) , but does it in blocking mode.

tpws uses async sockets for all activities. Domain names are resolved in multi threaded pool.
Resolving does not freeze other connections. But if there're too many requests resolving delays may increase.
Number of resolver threads is choosen automatically proportinally to `--maxconn` and can be overriden using `--resolver-threads`.
To disable hostname resolve use `--no-resolve` option.

`--disorder` is an additional flag to any split option.
It tries to simulate `--disorder2` option of `nfqws` using standard socket API without the need of additional privileges.
This works fine in Linux and MacOS but unexpectedly in FreeBSD and OpenBSD
(system sends second fragment then the whole packet instead of the first fragment).

`--tlsrec` and `--tlsrec-pos` allow to split TLS ClientHello into 2 TLS records in one TCP segment.
`--tlsrec=sni` splits between 1st and 2nd chars of the hostname. No split occurs if SNI is not present.
`--tlsrec-pos` splits at specified position. If TLS data block size is too small pos=1 is applied.
`--tlsrec` can be combined with `--split-pos` and `--disorder`.
`--tlsrec` breaks significant number of sites. Crypto libraries on end servers usually accept fine modified ClientHello
but middleboxes such as CDNs and ddos guards - not always.
Use of `--tlsrec` without filters is discouraged.

`--mss` sets TCP_MAXSEG socket option. Client sets this value in MSS TCP option in the SYN packet.
Server replies with it's own MSS in SYN,ACK packet. Usually servers lower their packet sizes but they still don't
fit to supplied MSS. The greater MSS client sets the bigger server's packets will be.
If it's enough to split TLS 1.2 ServerHello, it may fool DPI that checks certificate domain name.
This scheme may significantly lower speed. Hostlist filter is possible only in socks mode if client uses remote resolving (firefox `network.proxy.socks_remote_dns`).
TLS version filters are not possible.
`--mss-pf` sets port filter for MSS. Use `mss-pf=443` to apply MSS only for https.
Likely not required for TLS1.3. If TLS1.3 is negotiable then MSS make things only worse.
Use only if nothing better is available. Works only in Linux, not BSD or MacOS.


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

An alternative to ipset is to use tpws or nfqws with a list(s) of domains.
Both `tpws` and `nfqws` take any number of include (`--hostlist`) and exclude (`--hostlist-exclude`) domain lists.
All lists of the same type are combined internally leaving only 2 lists : include and exclude.

Exclude list is checked first. Fooling is cancelled if domain belongs to exclude list.
If include list is present and domain does not belong to that list fooling is also cancelled.
Empty list means absent list. Otherwise fooling goes on.

Launch system looks for 2 include lists :

`ipset/zapret-hosts-users.txt.gz` or `ipset/zapret-hosts-users.txt`

`ipset/zapret-hosts.txt.gz` or `ipset/zapret-hosts.txt`

and 1 exclude list

`ipset/zapret-hosts-users-exclude.txt.gz` or `ipset/zapret-hosts-users-exclude.txt`

If `MODE_FILTER=hostlist` all present lists are passed to `nfqws` or `tpws`.
If all include lists are empty it works like no include lists exist at all.
If you need "all except" mode you dont have to delete zapret-hosts-users.txt. Just make it empty.

Subdomains auto apply. For example, "ru" in the list affects "*.ru" .

tpws and nfqws reread lists on HUP signal.

When filtering by domain name, daemons should run without filtering by ipset.
When using large regulator lists estimate the amount of RAM on the router !

## **autohostlist** mode

This mode analyzes both client requests and server replies.
If a host is not in any list and a situation similar to block occurs host is automatically added to the special list both in memory and file.
Use exclude hostlist to prevent autohostlist triggering.
If it did happen - delete the undesired record from the file and restart tpws/nfqws or send them SIGHUP to force lists reload.

In case of nfqws it's required to redirect both incoming and outgoing traffic to the queue.
It's strongly recommended to use connbytes filter or nfqws will process gigabytes of incoming traffic.
For the same reason it's not recommended to use autohostlist mode in BSDs. BSDs do not support connbytes or similar mechanism.

nfqws и tpws detect the folowing situations :
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
Remove undesired domain from the autohostlist file, restart nfqws/tpws or send them SIGHUP.
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

Main mode :

```
tpws - tpws transparent mode
tpws-socks - tpws socks mode
 binds to localhost and LAN interface (if IFACE_LAN is specified or the system is OpenWRT). port 988
nfqws - nfqws
filter - only fill ipset or load hostlist
custom - use custom script for running daemons and establishing firewall rules
```

`MODE=tpws`

Enable http fooling :

`MODE_HTTP=1`

Apply fooling to keep alive http sessions. Only applicable to nfqws. Tpws always fool keepalives.
Not enabling this can save CPU time.

`MODE_HTTP_KEEPALIVE=0`

Enable https fooling :

`MODE_HTTPS=1`

Enable quic fooling :

`MODE_QUIC=1`

Host filtering mode :
```
none - apply fooling to all hosts
ipset - limit fooling to hosts from ipset zapret/zapret6
hostlist - limit fooling to hosts from hostlist
autohostlist - hostlist mode + blocks auto detection
```

`MODE_FILTER=none`

Its possible to change manipulation options used by tpws :

`TPWS_OPT="--hostspell=HOST --split-http-req=method --split-pos=3"`

nfqws options for DPI desync attack:

```
DESYNC_MARK=0x40000000
DESYNC_MARK_POSTNAT=0x20000000
NFQWS_OPT_DESYNC="--dpi-desync=fake --dpi-desync-ttl=0 --dpi-desync-fooling=badsum --dpi-desync-fwmark=$DESYNC_MARK"
```

Separate nfqws options for http and https and ip protocol versions 4,6:

```
NFQWS_OPT_DESYNC_HTTP="--dpi-desync=split --dpi-desync-ttl=0 --dpi-desync-fooling=badsum"
NFQWS_OPT_DESYNC_HTTPS="--wssize=1:6 --dpi-desync=split --dpi-desync-ttl=0 --dpi-desync-fooling=badsum"
NFQWS_OPT_DESYNC_HTTP6="--dpi-desync=split --dpi-desync-ttl=5 --dpi-desync-fooling=none"
NFQWS_OPT_DESYNC_HTTPS6="--wssize=1:6 --dpi-desync=split --dpi-desync-ttl=5 --dpi-desync-fooling=none"
```

If one of `NFQWS_OPT_DESYNC_HTTP`/`NFQWS_OPT_DESYNC_HTTPS` is not defined it takes value of NFQWS_OPT_DESYNC.
If one of `NFQWS_OPT_DESYNC_HTTP6`/`NFQWS_OPT_DESYNC_HTTPS6` is not defined it takes value from
`NFQWS_OPT_DESYNC_HTTP`/`NFQWS_OPT_DESYNC_HTTPS`.
It means if only `NFQWS_OPT_DESYNC` is defined all four take its value.

If a variable is not defined, the value `NFQWS_OPT_DESYNC` is taken.

Separate QUIC options for ip protocol versions :

```
NFQWS_OPT_DESYNC_QUIC="--dpi-desync=fake"
NFQWS_OPT_DESYNC_QUIC6="--dpi-desync=hopbyhop"
```

If `NFQWS_OPT_DESYNC_QUIC6` is not specified `NFQWS_OPT_DESYNC_QUIC` is taken.


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
`blockcheck.sh` works in Linux and FreeBSD.

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

### Android

Its not possible to use nfqws and tpws in transparent proxy mode without root privileges.
Without root tpws can run in --socks mode.

Android has NFQUEUE and nfqws should work.

There's no ipset support unless you run custom kernel. In common case task of bringing up ipset
on android is ranging from "not easy" to "almost impossible", unless you find working kernel
image for your device.

Android does not use /etc/passwd, `tpws --user` won't work. There's replacement.
Use numeric uids in `--uid` option.
Its recommended to use gid 3003 (AID_INET), otherwise tpws will not have inet access.

Example : `--uid 1:3003`

In iptables use : `! --uid-owner 1` instead of `! --uid-owner tpws`.

Nfqws should be executed with `--uid 1`. Otherwise on some devices or firmwares kernel may partially hang. Looks like processes with certain uids can be suspended. With buggy chineese cellular interface driver this can lead to device hang.

Write your own shell script with iptables and tpws, run it using your root manager.
Autorun scripts are here :

magisk  : `/data/adb/service.d`

supersu : `/system/su.d`

How to run tpws on root-less android.
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

see docs/bsd.eng.md

### Windows (WSL)

see docs/windows.eng.md

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
 * tpws can be run almost anywhere but nfqws require kernel support for NFQUEUE. Its missing in most firmwares.
 * too old 2.6 kernels are unsupported and can cause errors. newer 2.6 kernels are OK.
If binaries crash with segfault (rare but happens on some kernels) try to unpack upx like this : upx -d tpws.

First manually debug your scenario. Run iptables + daemon and check if its what you want.
Write your own script with iptables magic and run required daemon from there. Put it to startup.
Dont ask me how to do it. Its different for all firmwares and requires studying.
Find manual or reverse engineer yourself.
Check for race conditions. Firmware can clear or modify iptables after your startup script.
If this is the case then run another script in background and add some delay there.
