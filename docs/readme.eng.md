What is it for
--------------

A stand-alone (without 3rd party servers) DPI circumvention tool.
May allow to bypass http(s) website blocking or speed shaping, resist signature tcp protocol discovery.

The project is mainly aimed at the Russian audience to fight russian regulator named "Roskomnadzor".
Some features of the project are russian reality specific (such as getting list of sites
blocked by Roskomnadzor), but most others are common.

Mainly OpenWRT targeted but also supports traditional Linux, FreeBSD, OpenBSD, partially MacOS.

How it works
------------

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
For example, a request of the form "GET / HTTP / 1.1 \ r \ nHost: kinozal.tv ......"
we send in 2 parts: first go "GET", then "/ HTTP / 1.1 \ r \ nHost: kinozal.tv .....".
Other DPIs stumble when the "Host:" header is written in another case: for example, "host:".
Sometimes work adding extra space after the method: "GET /" => "GET  /"
or adding a dot at the end of the host name: "Host: kinozal.tv."

There is also more advanced magic for bypassing DPI at the packet level.


How to put this into practice in the linux system
-------------------------------------------------

In short, the options can be classified according to the following scheme:

1) Passive DPI not sending RST to the server. ISP tuned iptables commands can help.
This option is out of the scope of the project. If you do not allow ban trigger to fire, then you won’t have to
deal with its consequences.
2) Modification of the TCP connection at the stream level. Implemented through a proxy or transparent proxy.
3) Modification of TCP connection at the packet level. Implemented through the NFQUEUE handler and raw sockets.

For options 2 and 3, tpws and nfqws programs are implemented, respectively.
You need to run them with the necessary parameters and redirect certain traffic with iptables.

To redirect a TCP connection to a transparent proxy, the following commands are used:

forwarded traffic :
iptables -t nat -I PREROUTING -i <internal_interface> -p tcp --dport 80 -j DNAT --to 127.0.0.127:988
outgoing traffic :
iptables -t nat -I OUTPUT -o <external_interface> -p tcp --dport 80 -m owner ! --uid-owner tpws -j DNAT --to 127.0.0.127:988

DNAT on localhost works in the OUTPUT chain, but does not work in the PREROUTING chain without enabling the route_localnet parameter:

sysctl -w net.ipv4.conf.<internal_interface>.route_localnet=1

You can use "-j REDIRECT --to-port 988" instead of DNAT, but in this case the transparent proxy process
should listen on the ip address of the incoming interface or on all addresses. Listen all - not good
in terms of security. Listening one (local) is possible, but automated scripts will have to recognize it,
then dynamically enter it into the command. In any case, additional efforts are required.
Using route_localnet can also introduce some security risks. You make available from internal_interface everything
bound to 127.0.0.0/8. Services are usually bound to 127.0.0.1. Its possible to deny input to 127.0.0.1 from all interfaces except lo
or bind tpws to any other IP from 127.0.0.0/8 range, for example to 127.0.0.127, and allow incomings only to that IP :

iptables -A INPUT ! -i lo -d 127.0.0.127 -j ACCEPT
iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j DROP

Owner filter is necessary to prevent recursive redirection of connections from tpws itself.
tpws must be started under OS user "tpws".


NFQUEUE redirection of the outgoing traffic and forwarded traffic going towards the external interface,
can be done with the following commands:

iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp --dport 80 -j NFQUEUE --queue-num 200 --queue-bypass

In order not to touch the traffic to unblocked addresses, you can take a list of blocked hosts, resolve it
into IP addresses and put them to ipset 'zapret', then add a filter to the command:

iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp --dport 80 -m set --match-set zapret dst -j NFQUEUE --queue-num 200 --queue-bypass

Some DPIs catch only the first http request, ignoring subsequent requests in a keep-alive session.
Then we can reduce CPU load, refusing to process unnecessary packets.

iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp --dport 80 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:4 -m mark ! --mark 0x40000000/0x40000000 -m set --match-set zapret dst -j NFQUEUE --queue-num 200 --queue-bypass

Mark filter does not allow nfqws-generated packets to enter the queue again.
Its necessary to use this filter when also using "connbytes 1:4". Without it packet ordering can be changed breaking the whole idea.


ip6tables
---------

ip6tables work almost exactly the same way as ipv4, but there are a number of important nuances.
In DNAT, you should take the address --to in square brackets. For example :

 ip6tables -t nat -I OUTPUT -o <external_interface> -p tcp --dport 80 -m owner ! --uid-owner tpws -j DNAT --to [::1]:988

The route_localnet parameter does not exist for ipv6.
DNAT to localhost (:: 1) is possible only in the OUTPUT chain.
In the PREROUTING DNAT chain, it is possible to any global address or to the link local address of the same interface
the packet came from.
NFQUEUE works without changes.

When it will not work
----------------------

* If DNS server returns false responses. ISP can return false IP addresses or not return anything
when blocked domains are queried. If this is the case change DNS to public ones, such as 8.8.8.8 or 1.1.1.1.
Sometimes ISP hijacks queries to any DNS server. Dnscrypt or dns-over-tls help.
* If blocking is done by IP.
* If a connection passes through a filter capable of reconstructing a TCP connection, and which
follows all standards. For example, we are routed to squid. Connection goes through the full OS tcpip stack,
fragmentation disappears immediately as a means of circumvention. Squid is correct, it will find everything
as it should, it is useless to deceive him.
BUT. Only small providers can afford using squid, since it is very resource intensive.
Large companies usually use DPI, which is designed for much greater bandwidth.

nfqws
-----

This program is a packet modifier and a NFQUEUE queue handler.
For BSD systems there is dvtws. Its built from the same source and has almost the same parameters (see bsd.eng.txt).
nfqws takes the following parameters:

 --debug=0|1				; 1=print debug info
 --qnum=<nfqueue_number>
 --wsize=<winsize>[:<scale_factor>]	; change window size in SYN,ACK packets. default is not to change scale factor (OBSOLETE !)
 --wssize=<winsize>[:<scale_factor>]	; change window size in outgoing packets. default scale factor is 0. (see CONNTRACK)
 --wssize-cutoff=N                      ; apply server wsize only to packet numbers less than N
 --ctrack-timeouts=S:E:F                ; internal conntrack timeouts for SYN, ESTABLISHED and FIN stages. default 60:300:60
 --hostcase           			; change Host: => host:
 --hostspell=HoSt      			; exact spelling of the "Host" header. must be 4 chars. default is "host"
 --hostnospace         			; remove space after Host: and add it to User-Agent: to preserve packet size
 --domcase				; mix domain case after Host: like this : TeSt.cOm
 --daemon              			; daemonize
 --pidfile=<filename>  			; write pid to file
 --user=<username>      		; drop root privs
 --uid=uid[:gid]			; drop root privs
 --dpi-desync=[<mode0,]<mode>[,<mode2>]	; desync dpi state. modes : synack fake rst rstack disorder disorder2 split split2
 --dpi-desync-fwmark=<int|0xHEX>        ; override fwmark for desync packet. default = 0x40000000
 --dpi-desync-ttl=<int>                 ; set ttl for desync packet
 --dpi-desync-ttl6=<int>                ; set ipv6 hop limit for desync packet. by default ttl value is used
 --dpi-desync-fooling=none|md5sig|ts|badseq|badsum ; can take multiple comma separated values
 --dpi-desync-retrans=0|1               ; (fake,rst,rstack only) 0(default)=reinject original data packet after fake  1=drop original data packet to force its retransmission
 --dpi-desync-repeats=<N>               ; send every desync packet N times
 --dpi-desync-skip-nosni=0|1		; 1(default)=do not apply desync to requests without hostname in the SNI
 --dpi-desync-split-pos=<1..1500>	; (for split* and disorder* only) split TCP packet at specified position
 --dpi-desync-any-protocol=0|1		; 0(default)=desync only http and tls  1=desync any nonempty data packet
 --dpi-desync-fake-http=<filename>      ; file containing fake http request. replacement for built-in
 --dpi-desync-fake-tls=<filename>       ; file containing fake TLS ClientHello (for https). replacement for built-in
 --dpi-desync-cutoff=N                  ; apply dpi desync only to packet numbers less than N
 --hostlist=<filename>                  ; apply fooling only to the listed hosts (one host per line, subdomains auto apply)

The manipulation parameters can be combined in any way.

WARNING. --wsize parameter is now not used anymore in scripts. TCP split can be achieved using DPI desync attack.

DPI DESYNC ATTACK
After completion of the tcp 3-way handshake, the first data packet from the client goes.
It usually has "GET / ..." or TLS ClientHello. We drop this packet, replacing with something else.
It can be a fake version with another harmless but valid http or https request (fake), tcp reset packet (rst,rstack),
split into 2 segments original packet with fake segment in the middle (disorder).
In articles these attack have names "TCB desynchronization" and "TCB teardown".
Fake packet must reach DPI, but do not reach the destination server.
The following means are available: set a low TTL, send a packet with bad checksum,
add tcp option "MD5 signature". All of them have their own disadvantages :

* md5sig does not work on all servers
* badsum doesn't work if your device is behind NAT which does not pass invalid packets.
  The most common Linux NAT router configuration does not pass them. Most home routers are Linux based.
  The default sysctl configuration net.netfilter.nf_conntrack_checksum=1 causes contrack to verify tcp and udp checksums
  and set INVALID state for packets with invalid checksum.
  Typically, iptables rules include a rule for dropping packets with INVALID state in the FORWARD chain.
  The combination of these factors does not allow badsum packets to pass through the router.
  In openwrt mentioned sysctl is set to 0 from the box, in other routers its often left in the default "1" state.
  For nfqws to work properly through the router set net.netfilter.nf_conntrack_checksum=0 on the router.
  System never verifies checksums of locally generated packets so nfqws will always work on the router itself.
  If you are behind another NAT, such as a ISP, and it does not pass invalid packages, there is nothing you can do about it.
  But usually ISPs pass badsum.
* badsum doesn't work if your device is behind NAT which does not pass invalid packets.
  Linux NAT by default does not pass them without special setting "sysctl -w net.netfilter.nf_conntrack_checksum=0"
  Openwrt sets it from the box, other routers in most cases don't, and its not always possible to change it.
  If nfqws is on the router, its not necessary to switch of "net.netfilter.nf_conntrack_checksum".
  Fake packet doesn't go through FORWARD chain, it goes through OUTPUT. But if your router is behind another NAT, for example ISP NAT,
  and that NAT does not pass invalid packets, you cant do anything.
* badseq packets will be dropped by server, but DPI also can ignore them
* TTL looks like the best option, but it requires special tuning for each ISP. If DPI is further than local ISP websites
  you can cut access to them. Manual IP exclude list is required. Its possible to use md5sig with ttl.
  This way you cant hurt anything, but good chances it will help to open local ISP websites.
  If automatic solution cannot be found then use zapret-hosts-user-exclude.txt.

--dpi-desync-fooling takes multiple comma separated values.

For fake,rst,rstack modes original packet can be sent after the fake one or just dropped.
If its dropped OS will perform first retransmission after 0.2 sec, then the delay increases exponentially.
Delay can help to make sure fake and original packets are properly ordered and processed on DPI.
When dpi-desync-retrans=1 its mandatory to use connbytes in iptables rule. Otherwise loop happens.

Disorder mode splits original packet and sends packets in the following order :
1. 2nd segment
2. fake 1st segment, data filled with zeroes
3. 1st segment
4. fake 1st segment, data filled with zeroes (2nd copy)
Original packet is always dropped. --dpi-desync-split-pos sets split position (default 3).
If position is higher than packet length, pos=1 is used.
This sequence is designed to make reconstruction of critical message as difficult as possible.
Fake segments may not be required to bypass some DPIs, but can potentially help if more sophisticated reconstruction
algorithms are used.
Mode 'disorder2' disables sending of fake segments.

Split mode is very similar to disorder but without segment reordering :
1. fake 1st segment, data filled with zeroes
2. 1st segment
3. fake 1st segment, data filled with zeroes (2nd copy)
4. 2nd segment
Mode 'split2' disables sending of fake segments. It can be used as a faster alternative to --wsize.

In disorder2 and split2 modes no fake packets are sent, so ttl and fooling options are not required.

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

iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:4 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass

This is good if DPI does not track all requests in http keep-alive session.
If it does, then pass all outgoing packets for http and only first data packet for https :

iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp --dport 443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:4 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
iptables -t mangle -I POSTROUTING -o <external_interface> -p tcp --dport 80 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass

mark is needed to keep away generated packets from NFQUEUE. nfqws sets fwmark when it sends generated packets.
nfqws can internally filter marked packets. but when connbytes filter is used without mark filter
packet ordering can be changed breaking the whole idea of desync attack.

DPI DESYNC COMBOS
dpi-desync parameter takes up to 3 comma separated arguments.
zero phase means tcp connection establishement (before sending data payload). Mode can be "synack".
Hostlist filter is not applicable to the zero phase.
Next phases work on packets with data payload.
1st phase mode can be fake,rst,rstack, 2nd phase mode - disorder,disorder2,split,split2.
Can be useful for ISPs with more than one DPI.

SYNACK MODE
In geneva docs it's called "TCP turnaround". Attempt to make the DPI believe the roles of client and server are reversed.
!!! This mode breaks NAT operation and can be used only if there's no NAT between the attacker's device and the DPI !
In linux it's required to remove standard firewall rule dropping INVALID packets in the OUTPUT chain,
for example : -A OUTPUT -m state --state INVALID -j DROP
In openwrt it's possible to disable the rule for both FORWARD and OUTPUT chains in /etc/config/firewall :
config zone
	option name 'wan'
	.........
	option masq_allow_invalid '1'
Unfortunately there's no OUTPUT only switch. It's not desired to remove the rule from the FORWARD chain.
Add the following lines to /etc/firewall.user :

iptables -D zone_wan_output -m comment --comment '!fw3' -j zone_wan_dest_ACCEPT
ip6tables -D zone_wan_output -m comment --comment '!fw3' -j zone_wan_dest_ACCEPT

then /etc/init.d/firewall restart

Otherwise raw sending SYN,ACK frame will cause error stopping the further processing.
If you realize you don't need the synack mode it's highly suggested to restore drop INVALID rule.

VIRTUAL MACHINES
Most of nfqws packet magic does not work from VMs powered by virtualbox and vmware when network is NATed.
Hypervisor forcibly changes ttl and does not forward fake packets.
Set up bridge networking.


CONNTRACK
nfqws is equipped with minimalistic connection tracking system (conntrack)
It's enabled if some specific DPI circumvention methods are involved.
Currently these are --wssize and --dpi-desync-cutoff  options.
Conntrack can track connection phase : SYN,ESTABLISHED,FIN , packet counts in both directions , sequence numbers.
It can be fed with unidirectional or bidirectional packets.
A SYN or SYN,ACK packet creates an entry in the conntrack table.
That's why iptables redirection must start with the first packet although can be cut later using connbytes filter.
A connection is deleted from the table as soon as it's no more required to satisfy nfqws needs or when a timeout happens.
There're 3 timeouts for each connection state. They can be changed in --ctrack-timeouts parameter.

--wssize changes tcp window size for the server to force it to send split replies.
In order for this to affect all server operating systems, it is necessary to change the window size in each outgoing packet
before sending the message, the answer to which must be split (for example, TLS ClientHello).
That's why conntrack is required to know when to stop applying low window size.
If you do not stop and set the low wssize all the time, the speed will drop catastrophically.
Linux can overcome this using connbytes filter but other OS may not include similar filter.
In http(s) case wssize stops after the first http request or TLS ClientHello.
If you deal with a non-http(s) protocol you need --wssize-cutoff. It sets the number of the outgoing packet where wssize stops.
(numbering starts from 1). 
If a http request or TLS ClientHello packet is detected wssize stops immediately ignoring wssize-cutoff option.
If your protocol is prone to long inactivity, you should increase ESTABLISHED phase timeout using --ctrack-timeouts.
Default timeout is low - only 5 mins.
Don't forget that nfqws feeds with redirected packets. If you have limited redirection with connbytes
ESTABLISHED entries can remain in the table until dropped by timeout.
To diagnose conntrack state send SIGUSR1 signal to nfqws : killall -SIGUSR1 nfqws.
nfqws will dump current conntrack table to stdout.

Typically, in a SYN packet, client sends TCP extension "scaling factor" in addition to window size.
scaling factor is the power of two by which the window size is multiplied : 0=>1, 1=>2, 2=>4, ..., 8=>256, ...
The wssize parameter specifies the scaling factor after a colon.
Scaling factor can only decrease, increase is blocked to prevent the server from exceeding client's window size.
To force a TLS server to fragment ServerHello message to avoid hostname detection on DPI use --wssize=1:6
The main rule is to set scale_factor as much as possible so that after recovery the final window size
becomes the possible maximum. If you set scale_factor 64:0, it will be very slow.
On the other hand, the server response must not be large enough for the DPI to find what it is looking for.

Hostlist filter does not affect --wssize because it works since the connection initiation when it's not yet possible
to extract the host name.
--wssize may slow down sites and/or increase response time. It's desired to use another methods if possible.

--dpi-desync-cutoff allows you to set the limit on the number of the outgoing packet, at which it stops
applying dpi-desync. Useful with --dpi-desync-any-protocol=1.
If the connection falls out of the conntrack and --dpi-desync-cutoff is set, dpi desync will not be applied.
Set conntrack timeouts appropriately.


tpws
-----

tpws is transparent proxy.

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
 --skip-nodelay			; do not set TCP_NODELAY for outgoing connections. incompatible with split.
 --no-resolve			; disable socks5 remote dns
 --maxconn=<max_connections>	; max number of local legs
 --maxfiles=<max_open_files>    ; max file descriptors (setrlimit). min requirement is (X*connections+16), where X=6 in tcp proxy mode, X=4 in tampering mode.
				; its worth to make a reserve with 1.5 multiplier. by default maxfiles is (X*connections)*1.5+16
 --max-orphan-time=<sec>	; if local leg sends something and closes and remote leg is still connecting then cancel connection attempt after N seconds

 --hostlist=<filename>          ; only act on host in the list (one host per line, subdomains auto apply, gzip lists supported)
 --split-http-req=method|host	; split http request at specified logical position.
 --split-pos=<numeric_offset>   ; split at specified pos. split-http-req takes precedence over split-pos for http reqs.
 --split-any-protocol		; split not only http and https
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
 --daemon                       ; daemonize
 --pidfile=<filename>           ; write pid to file
 --user=<username>              ; drop root privs
 --uid=uid[:gid]		; drop root privs

The manipulation parameters can be combined in any way.

split-http-req takes precedence over split-pos for http reqs.
split-pos works by default only on http and TLS ClientHello. use --split-any-protocol to act on any packet

tpws can bind to multiple interfaces and IP addresses (up to 32).
Port number is always the same.
Parameters --bind-iface* and --bind-addr create new bind.
Other parameters --bind-* are related to the last bind.
link local ipv6 (fe80::/8) mode selection :
--bind-iface6 --bind-linklocal=no : first selects private address fd00::/8, then global address
--bind-iface6 --bind-linklocal=unwanted : first selects private address fd00::/8, then global address, then LL
--bind-iface6 --bind-linklocal=prefer : first selects LL, then private address fd00::/8, then global address
--bind-iface6 --bind-linklocal=force : select only LL
To bind to all ipv4 specify --bind-addr "0.0.0.0", all ipv6 - "::". --bind-addr="" - mean bind to all ipv4 and ipv6.
If no binds are specified default bind to all ipv4 and ipv6 addresses is created.
To bind to a specific link local address do : --bind-iface6=fe80::aaaa:bbbb:cccc:dddd%iface-name
The --bind-wait* parameters can help in situations where you need to get IP from the interface, but it is not there yet, it is not raised
or not configured.
In different systems, ifup events are caught in different ways and do not guarantee that the interface has already received an IP address of a certain type.
In the general case, there is no single mechanism to hang oneself on an event of the type "link local address appeared on the X interface."
To bind to a specific ip when its interface may not be configured yet do : --bind-addr=192.168.5.3 --bind-wait-ip=20
It's possible to bind to any nonexistent address in transparent mode but in socks mode address must exist.

in socks proxy mode no additional system privileges are required
connection to local IPs of the system where tpws runs are prohibited
tpws supports remote dns resolving (curl : --socks5-hostname  firefox : socks_remote_dns=true) , but does it in blocking mode.
tpws uses async sockets for all activity but resolving can break this model.
if tpws serves many clients it can cause trouble. also DoS attack is possible against tpws.
if remote resolving causes trouble configure clients to use local name resolution and use
--no-resolve option on tpws side.

Ways to get a list of blocked IP
--------------------------------

1) Enter the blocked domains to ipset/zapret-hosts-user.txt and run ipset/get_user.sh
At the output, you get ipset/zapret-ip-user.txt with IP addresses.

2) ipset/get_reestr_*.sh. Russian specific

3) ipset/get_antifilter_*.sh. Russian specific

4) ipset/get_config.sh. This script calls what is written into the GETLIST variable from the config file.
If the variable is not defined, then only lists for ipsets nozapret/nozapret6 are resolved.

So, if you're not russian, the only way for you is to manually add blocked domains.
Or write your own ipset/get_iran_blocklist.sh , if you know where to download this one.

On routers, it is not recommended to call these scripts more than once in 2 days to minimize flash memory writes.

ipset/create_ipset.sh executes forced ipset update.
With "no-update" parameter create_ipset.sh creates ipset but populate it only if it was actually created.
It's useful when multiple subsequent calls are possible to avoid wasting of cpu time redoing the same job.
Ipset loading is resource consuming. Its a good idea to call create_ipset without "no-update" parameter
only once a several days. Use it with "no-update" option in other cases.

ipset scripts automatically call ip2net utility.
ip2net helps to reduce ip list size by combining IPs to subnets. Also it cuts invalid IPs from the list.
Stored lists are already processed by ip2net. They are error free and ready for loading.

create_ipset.sh supports loading ip lists from gzip files. First it looks for the filename with the ".gz" extension,
such as "zapret-ip.txt.gz", if not found it falls back to the original name "zapret-ip.txt".
So your own get_iran_blockslist.sh can use "zz" function to produce gz. Study how other russian get_XXX.sh work.
Gzipping helps saving a lot of precious flash space on embedded systems.
User lists are not gzipped because they are not expected to be very large.

You can add a list of domains to ipset/zapret-hosts-user-ipban.txt. Their ip addresses will be placed
in a separate ipset "ipban". It can be used to route connections to transparent proxy "redsocks" or VPN.

IPV6: if ipv6 is enabled, then additional txt's are created with the same name, but with a "6" at the end before the extension.
zapret-ip.txt => zapret-ip6.txt
The ipsets zapret6 and ipban6 are created.

IP EXCLUSION SYSTEM. All scripts resolve zapret-hosts-user-exclude.txt file, creating zapret-ip-exclude.txt and zapret-ip-exclude6.txt.
They are the source for ipsets nozapret/nozapret6. All rules created by init scripts are created with these ipsets in mind.
The IPs placed in them are not involved in the process.
zapret-hosts-user-exclude.txt can contain domains, ipv4 and ipv6 addresses or subnets.

FreeBSD. ipset/*.sh scripts also work in FreeBSD. Instead of ipset they create ipfw lookup tables with the same names as in Linux.
ipfw tables can store both ipv4 and ipv6 addresses and subnets. There's no 4 and 6 separation.

LISTS_RELOAD config parameter defines a custom lists reloading command.
Its useful on BSD systems with PF.
LISTS_RELOAD=-  disables reloading ip list backend.


Domain name filtering
---------------------

An alternative to ipset is to use tpws or nfqws with a list of domains. Only one list is supported.

Enter the blocked domains to ipset/zapret-hosts-users.txt. Remove ipset/zapret-hosts.txt.gz.
Then the init script will run tpws with the zapret-hosts-users.txt list.

Other option ( Roskomnadzor list - get_hostlist.sh ) is russian specific.
You can write your own replacement for get_hostlist.sh.

When filtering by domain name, daemons should run without filtering by ipset.
When using large regulator lists estimate the amount of RAM on the router !


Choosing parameters
-------------------

The file /opt/zapret/config is used by various components of the system and contains basic settings.
It needs to be viewed and edited if necessary.


Main mode :
tpws - tpws transparent mode
tpws-socks - tpws socks mode
 binds to localhost and LAN interface (if IFACE_LAN is specified or the system is OpenWRT). port 988
nfqws - nfqws
filter - only fill ipset or load hostlist
custom - use custom script for running daemons and establishing firewall rules

MODE=tpws

Enable http fooling :

MODE_HTTP=1

Apply fooling to keep alive http sessions. Only applicable to nfqws. Tpws always fool keepalives.
Not enabling this can save CPU time.

MODE_HTTP_KEEPALIVE=0

Enable https fooling :

MODE_HTTPS=1

Host filtering mode :
none - apply fooling to all hosts
ipset - limit fooling to hosts from ipset zapret/zapret6
hostlist - limit fooling to hosts from hostlist

MODE_FILTER=none

Its possible to change manipulation options used by tpws :

TPWS_OPT="--hostspell=HOST --split-http-req=method --split-pos=3"

nfqws options for DPI desync attack:

DESYNC_MARK=0x40000000
NFQWS_OPT_DESYNC="--dpi-desync=fake --dpi-desync-ttl=0 --dpi-desync-fooling=badsum --dpi-desync-fwmark=$DESYNC_MARK"

Separate nfqws options for http and https and ip protocol versions 4,6:

NFQWS_OPT_DESYNC_HTTP="--dpi-desync=split --dpi-desync-ttl=0 --dpi-desync-fooling=badsum"
NFQWS_OPT_DESYNC_HTTPS="--wssize=1:6 --dpi-desync=split --dpi-desync-ttl=0 --dpi-desync-fooling=badsum"
NFQWS_OPT_DESYNC_HTTP6="--dpi-desync=split --dpi-desync-ttl=5 --dpi-desync-fooling=none"
NFQWS_OPT_DESYNC_HTTPS6="--wssize=1:6 --dpi-desync=split --dpi-desync-ttl=5 --dpi-desync-fooling=none"

If one of NFQWS_OPT_DESYNC_HTTP/NFQWS_OPT_DESYNC_HTTPS is not defined it takes value of NFQWS_OPT_DESYNC.
If one of NFQWS_OPT_DESYNC_HTTP6/NFQWS_OPT_DESYNC_HTTPS6 is not defined it takes value from
NFQWS_OPT_DESYNC_HTTP/NFQWS_OPT_DESYNC_HTTPS.
It means if only NFQWS_OPT_DESYNC is defined all four take its value.

If a variable is not defined, the value NFQWS_OPT_DESYNC is taken.

flow offloading control (openwrt only)
donttouch : disable system flow offloading setting if selected mode is incompatible with it, dont touch it otherwise and dont configure selective flow offloading
none : always disable system flow offloading setting and dont configure selective flow offloading
software : always disable system flow offloading setting and configure selective software flow offloading
hardware : always disable system flow offloading setting and configure selective hardware flow offloading

FLOWOFFLOAD=donttouch

The GETLIST parameter tells the install_easy.sh installer which script to call
to update the list of blocked ip or hosts.
Its called via get_config.sh from scheduled tasks (crontab or systemd timer).
Put here the name of the script that you will use to update the lists.
If not, then the parameter should be commented out.

You can individually disable ipv4 or ipv6. If the parameter is commented out or not equal to "1",
use of the protocol is permitted.
#DISABLE_IPV4=1
DISABLE_IPV6=1

The number of threads for mdig multithreaded DNS resolver (1..100).
The more of them, the faster, but will your DNS server be offended by hammering ?
MDIG_THREADS=30

temp directory. Used by ipset/*.sh scripts for large lists processing.
/tmp by default. Can be reassigned if /tmp is tmpfs and RAM is low.
TMPDIR=/opt/zapret/tmp

ipset options :

IPSET_OPT="hashsize 262144 maxelem 2097152"

Kernel automatically increases hashsize if ipset is too large for the current hashsize.
This procedure requires internal reallocation and may require additional memory.
On low RAM systems it can cause errors.
Do not use too high hashsize. This way you waste your RAM. And dont use too low hashsize to avoid reallocs.

ip2net options. separate for ipv4 and ipv6.
IP2NET_OPT4="--prefix-length=22-30 --v4-threshold=3/4"
IP2NET_OPT6="--prefix-length=56-64 --v6-threshold=5"

Enable gzip compression for large lists. Used by ipset/*.sh scripts.
GZIP_LISTS=1

Command to reload ip/host lists after update.
Comment or leave empty for auto backend selection : ipset or ipfw if present.
On BSD systems with PF no auto reloading happens. You must provide your own command.
Newer FreeBSD versions support table only reloading : pfctl -Tl -f /etc/pf.conf
Set to "-" to disable reload.
LISTS_RELOAD="pfctl -f /etc/pf.conf"

In openwrt there's default network 'lan'. Only traffic coming from this network is redirected to tpws by default.
To override this behaviour set the following variable :
OPENWRT_LAN="lan lan2 lan3"

The following settings are not relevant for openwrt :

If your system works as a router, then you need to enter the names of the internal and external interfaces:
IFACE_LAN = eth0
IFACE_WAN = eth1
IMPORTANT: configuring routing, masquerade, etc. not a zapret task.
Only modes that intercept transit traffic are enabled.
It's possible to specify multiple interfaces like this : IFACE_LAN="eth0 eth1 eth2"

The INIT_APPLY_FW=1 parameter enables the init script to independently apply iptables rules.
With other values or if the parameter is commented out, the rules will not be applied.
This is useful if you have a firewall management system, in the settings of which you should tie the rules.


Screwing to the firewall control system or your launch system
-------------------------------------------------------------

If you use some kind of firewall management system, then it may conflict with an existing startup script.
When re-applying the rules, it could break the iptables settings from the zapret.
In this case, the rules for iptables should be screwed to your firewall separately from running tpws or nfqws.

The following calls allow you to apply or remove iptables rules separately:

 /opt/zapret/init.d/sysv/zapret start-fw
 /opt/zapret/init.d/sysv/zapret stop-fw

And you can start or stop the demons separately from the firewall:

 /opt/zapret/init.d/sysv/zapret start-daemons
 /opt/zapret/init.d/sysv/zapret stop-daemons


Simple install to desktop linux system
--------------------------------------

Simple install works on most modern linux distributions with systemd or openrc, OpenWRT and MacOS.
Run install_easy.sh and answer its questions.

Simple install to openwrt
-------------------------

install_easy.sh works on openwrt but there're additional challenges.
They are mainly about possibly low flash free space.
Simple install will not work if it has no space to install itself and required packages from the repo.

Another challenge would be to bring zapret to the router. You can download zip from github and use it.
Do not repack zip contents in Windows, because this way you break chmod and links.
Install openssh-sftp-server and unzip to openwrt and use sftp to transfer the file.

The best way to start is to put zapret dir to /tmp and run /tmp/zapret/install_easy.sh from there.
After installation remove /tmp/zapret to free RAM.

The absolute minimum for openwrt is 64/8 system, 64/16 is comfortable, 128/extroot is recommended.


Android
-------

Its not possible to use nfqws and tpws in transparent proxy mode without root privileges.
Without root tpws can run in --socks mode.

I have no NFQUEUE presence statistics in stock android kernels, but its present on my MTK device.
If NFQUEUE is present nfqws works.

There's no ipset support unless you run custom kernel. In common case task of bringing up ipset
on android is ranging from "not easy" to "almost impossible", unless you find working kernel
image for your device.

Android does not use /etc/passwd, tpws --user won't work. There's replacement.
Use numeric uids in --uid option.
Its recommended to use gid 3003 (AID_INET), otherwise tpws will not have inet access.
Example : --uid 1:3003
In iptables use : "! --uid-owner 1" instead of "! --uid-owner tpws".

Write your own shell script with iptables and tpws, run it using your root manager.
Autorun scripts are here :
magisk  : /data/adb/service.d
supersu : /system/su.d

I haven't checked whether android can kill iptable rules at its own will during wifi connection/disconnection,
mobile data on/off, ...

How to run tpws on root-less android.
You can't write to /system, /data, can't run from sd card.
Selinux prevents running executables in /data/local/tmp from apps.
Use adb and adb shell.
mkdir /data/local/tmp/zapret
adb push tpws /data/local/tmp/zapret
chmod 755 /data/local/tmp/zapret /data/local/tmp/zapret/tpws
chcon u:object_r:system_file:s0 /data/local/tmp/zapret/tpws
Now its possible to run /data/local/tmp/zapret/tpws from any app such as tasker.


FreeBSD, OpenBSD, MacOS
-----------------------

see docs/bsd.eng.txt


Windows (WSL)
-------------

Using WSL (Windows subsystem for Linux) it's possible to run tpws in socks mode under rather new builds of
windows 10 and windows server.
Its not required to install any linux distributions as suggested in most articles.
tpws is static binary. It doesn't need a distribution.

Install WSL : dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all
Copy binaries/x86_64/tpws_wsl.tgz to the target system.
Run : wsl --import tpws "%USERPROFILE%\tpws" tpws_wsl.tgz
Run tpws : wsl --exec /tpws --uid=1 --no-resolve --socks --bind-addr=127.0.0.1 --port=1080 <fooling_options>
Configure socks as 127.0.0.1:1080 in a browser or another program.

Cleanup : wsl --unregister tpws

Tested in windows 10 build 19041 (20.04).

NOTICE. There is native windows solution GoodByeDPI. It works on packet level like nfqws.


Other devices
-------------

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
 * too old 2.6 kernels are unsupported and can cause errors
If binaries crash with segfault (rare but happens on some kernels) try to unpack upx like this : upx -d tpws.
First manually debug your scenario. Run iptables + daemon and check if its what you want.
Write your own script with iptables magic and run required daemon from there. Put it to startup.
Dont ask me how to do it. Its different for all firmwares and requires studying.
Find manual or reverse engineer yourself.
Check for race conditions. Firmware can clear or modify iptables after your startup script.
If this is the case then run another script in background and add some delay there.

