What is it for
--------------

Bypass the blocking of http/https web sites on DPI without the use of third-party servers.

The project is mainly aimed at the Russian audience to fight russian regulator named "Roskomnadzor".
Some features of the project are russian reality specific (such as getting list of sites
blocked by Roskomnadzor), but most others are common.

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

forwarded fraffic :
iptables -t nat -I PREROUTING -i <internal_interface> -p tcp --dport 80 -j DNAT --to 127.0.0.1:1188
outgoing traffic :
iptables -t nat -I OUTPUT -o <external_interface> -p tcp --dport 80 -m owner ! --uid-owner tpws -j DNAT --to 127.0.0.1:1188

DNAT on localhost works in the OUTPUT chain, but does not work in the PREROUTING chain without enabling the route_localnet parameter:

sysctl -w net.ipv4.conf.<internal_interface>.route_localnet=1

You can use "-j REDIRECT --to-port 1188" instead of DNAT, but in this case the transparent proxy process
should listen on the ip address of the incoming interface or on all addresses. Listen all - not good
in terms of security. Listening one (local) is possible, but automated scripts will have to recognize it,
then dynamically enter it into the command. In any case, additional efforts are required.

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

iptables -t mangle -I POSTROUTING -o <внешний_интерфейс> -p tcp --dport 80 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 2:4 -m set --match-set zapret dst -j NFQUEUE --queue-num 200 --queue-bypass


ip6tables
---------

ip6tables work almost exactly the same way as ipv4, but there are a number of important nuances.
In DNAT, you should take the address --to in square brackets. For example :

 iptables -t nat -I OUTPUT -p tcp --dport 80 -m owner ! --uid-owner tpws -j DNAT --to [::1]:1188

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
It takes the following parameters:

 --debug=0|1				; 1=print debug info
 --qnum=<nfqueue_number>
 --wsize=<window_size> 			; set window size. 0 = do not modify (obsolete !)
 --hostcase           			; change Host: => host:
 --hostspell=HoSt      			; exact spelling of the "Host" header. must be 4 chars. default is "host"
 --hostnospace         			; remove space after Host: and add it to User-Agent: to preserve packet size
 --daemon              			; daemonize
 --pidfile=<filename>  			; write pid to file
 --user=<username>      		; drop root privs
 --uid=uid[:gid]			; drop root privs
 --dpi-desync[=<mode>]			; try to desync dpi state. modes : fake rst rstack disorder disorder2 split split2
 --dpi-desync-fwmark=<int|0xHEX>        ; override fwmark for desync packet. default = 0x40000000
 --dpi-desync-ttl=<int>                 ; set ttl for desync packet
 --dpi-desync-fooling=none|md5sig|ts|badseq|badsum ; can take multiple comma separated values
 --dpi-desync-retrans=0|1               ; (fake,rst,rstack only) 0(default)=reinject original data packet after fake  1=drop original data packet to force its retransmission
 --dpi-desync-skip-nosni=0|1		; 1(default)=do not apply desync to requests without hostname in the SNI
 --dpi-desync-split-pos=<1..1500>	; (for disorder only) split TCP packet at specified position
 --dpi-desync-any-protocol=0|1		; 0(default)=desync only http and tls  1=desync any nonempty data packet
 --hostlist=<filename>                  ; apply dpi desync only to the listed hosts (one host per line, subdomains auto apply)

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
  Linux NAT by default does not pass them without special setting "sysctl -w net.netfilter.nf_conntrack_checksum=0"
  Openwrt sets it from the box, other routers in most cases dont, and its not always possible to change it.
  If nfqws is on the router, its not neccessary to switch of "net.netfilter.nf_conntrack_checksum".
  Fake packet doesn't go through FORWARD chain, it goes through OUTPUT. But if your router is behind another NAT, for example ISP NAT,
  and that NAT does not pass invalid packets, you cant do anything.
* badseq packets will be dropped by server, but DPI also can ignore them
* TTL looks like the best option, but it requires special tuning for earch ISP. If DPI is further than local ISP websites
  you can cut access to them. Manual IP exclude list is required. Its possible to use md5sig with ttl.
  This way you cant hurt anything, but good chances it will help to open local ISP websites.
  If automatic solution cannot be found then use zapret-hosts-user-exclude.txt.

--dpi-desync-fooling takes multiple comma separated values.

For fake,rst,rstack modes original packet can be sent after the fake one or just dropped.
If its dropped OS will perform first retransmission after 0.2 sec, then the delay increases exponentially.
Delay can help to make sure fake and original packets are properly ordered and processed on DPI.

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
1. 1st segment
2. fake 1st segment, data filled with zeroes
3. fake 1st segment, data filled with zeroes (2nd copy)
4. 2nd segment
Mode 'split2' disables sending of fake segments. It can be used as a faster alternative to --wsize.

In disorder2 and split2 modes no fake packets are sent, so no fooling options are required.

There are DPIs that analyze responses from the server, particularly the certificate from the ServerHello
that contain domain name(s). The ClientHello delivery confirmation is an ACK packet from the server
with ACK sequence number corresponding to the length of the ClientHello+1.
In the disorder variant, a selective acknowledgement (SACK) usually arrives first, then a full ACK.
If, instead of ACK or SACK, there is an RST packet with minimal delay, DPI cuts you off at the request stage.
If the RST is after a full ACK after a delay of about ping to the server, then probably DPI acts
on the server response. The DPI may be satisfied with good ClientHello and stop monitoring the TCP session
without checking ServerHello. Then you were lucky. 'fake' option could work.
If it does not stop monitoring and persistently checks the ServerHello, also performing reconstruction of TCP segments,
doing something about it is hardly possible without the help of the server.
The best solution is to enable TLS 1.3 support on the server. TLS 1.3 sends the server certificate in encrypted form.
This is recommendation to all admins of blocked sites. Enable TLS 1.3. You will give more opportunities to overcome DPI.

Hostlist is applicable only to desync attack. It does not work for other options.
Hosts are extracted from plain http request Host: header and SNI of ClientHelllo TLS message.
Subdomains are applied automatically. gzip lists are supported.

iptables for performing the attack on the first packet :

iptables -t mangle -I POSTROUTING -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 2:4 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass

This is good if DPI does not track all requests in http keep-alive session.
If it does, then pass all outgoing packets for http and only first data packet for https :

iptables -t mangle -I POSTROUTING -p tcp --dport 80 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 2:4 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass
iptables -t mangle -I POSTROUTING -p tcp --dport 443 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass

mark is needed to keep away generated packets from NFQUEUE. nfqws sets fwmark when it sends generated packets.

tpws
-----

tpws is transparent proxy.

 --debug=0|1|2			; 0(default)=silent 1=verbose 2=debug
 --bind-addr=<ipv4_addr>|<ipv6_addr>
 --bind-iface4=<interface_name> ; bind to the first ipv4 addr of interface
 --bind-iface6=<interface_name> ; bind to the first ipv6 addr of interface
 --bind-linklocal=prefer|force  ; prefer or force ipv6 link local
 --bind-wait-ifup=<sec>         ; wait for interface to appear and up
 --bind-wait-ip=<sec>           ; after ifup wait for ip address to appear up to N seconds
 --bind-wait-ip-linklocal=<sec> ; accept only link locals first N seconds then any
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

 --hostlist=<filename>          ; only act on host in the list (one host per line, subdomains auto apply)
 --split-http-req=method|host	; split http request at specified logical position
 --split-pos=<numeric_offset>   ; split at specified pos. invalidates split-http-req.
 --hostcase                     ; change Host: => host:
 --hostspell                    ; exact spelling of "Host" header. must be 4 chars. default is "host"
 --hostdot                      ; add "." after Host: name
 --hosttab                      ; add tab after Host: name
 --hostnospace                  ; remove space after Host:
 --hostpad=<bytes>		; add dummy padding headers before Host:
 --methodspace                  ; add extra space after method
 --methodeol                    ; add end-of-line before method
 --unixeol                      ; replace 0D0A to 0A
 --daemon                       ; daemonize
 --pidfile=<filename>           ; write pid to file
 --user=<username>              ; drop root privs
 --uid=uid[:gid]		; drop root privs
 
The manipulation parameters can be combined in any way.
There are exceptions: split-pos replaces split-http-req. hostdot and hosttab are mutually exclusive.
Only split-pos option works for non-HTTP traffic.

tpws can bind only to one ip or to all at once.
To bind to all ipv4, specify "0.0.0.0", to all ipv6 - "::". Without parameters, tpws bind to all ipv4 and ipv6.
The --bind-wait * parameters can help in situations where you need to get IP from the interface, but it is not there yet, it is not raised
or not configured.
In different systems, ifup events are caught in different ways and do not guarantee that the interface has already received an IP address of a certain type.
In the general case, there is no single mechanism to hang oneself on an event of the type "link local address appeared on the X interface."

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
The regulator list has already reached an impressive size of hundreds of thousands of IP addresses. Therefore, to optimize ipset
ip2net utility is used. It takes a list of individual IP addresses and tries to find in it subnets of the maximum size (from / 22 to / 30),
in which more than 3/4 addresses are blocked. ip2net is written in C because the operation is resource intensive.
If ip2net is compiled or a binary is copied to the ip2net directory, the create_ipset.sh script uses an ipset of the hash:net type,
piping the list through ip2net. Otherwise, ipset of hash:ip type is used, the list is loaded as is.
Accordingly, if you don’t like ip2net, just remove the binary from the ip2net directory.
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

Domain name filtering
---------------------

An alternative to ipset is to use tpws with a list of domains.
tpws can only read one hostlist.

Enter the blocked domains to ipset/zapret-hosts-users.txt. Remove ipset/zapret-hosts.txt.gz.
Then the init script will run tpws with the zapret-hosts-users.txt list.

Other option ( Roskomnadzor list - get_hostlist.sh ) is russian specific.
You can write your own replacement for get_hostlist.sh.

When filtering by domain name, tpws should run without filtering by ipset.
All http traffic goes through tpws, and it decides whether to use manipulation depending on the Host: field in the http request.
This creates an increased load on the system.
The domain search itself works very quickly, the load is connected with pumping the amount of data through the process.
When using large regulator lists estimate the amount of RAM on the router!

Choosing parameters
-------------------

The file /opt/zapret/config is used by various components of the system and contains basic settings.
It needs to be viewed and edited if necessary.
Select MODE:

nfqws_all_desync - use nfqws for DPI desync attack on all http and https
nfqws_ipset_desync - use nfqws for DPI desync attack on http and https , targets filtered by ipset "zapret"
nfqws_hostlist_desync - use nfqws for DPI desync attack on http and https , only to hostnames from hostlist

tpws_ipset - use tpws on http, targets are filtered by ipset "zapret"
tpws_ipset_https - use tpws on http and https, targets are filtered by ipset "zapret"
tpws_all - use tpws on all http
tpws_all_https - use tpws on all http and https
tpws_hostlist - same as tpws_all but touch only domains from the hostlist

ipset - only fill ipset. futher actions depend on your own code

Its possible to change manipulation options used by the daemons :

TPWS_OPT_HTTP="--hostspell=HOST --split-http-req=method"
TPWS_OPT_HTTPS="--split-pos=3"

Options for DPI desync attack are configured separately:

DESYNC_MARK=0x40000000
NFQWS_OPT_DESYNC="--dpi-desync=fake --dpi-desync-ttl=0 --dpi-desync-fooling=badsum --dpi-desync-fwmark=$DESYNC_MARK"


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

The following settings are not relevant for openwrt :

If your system works as a router, then you need to enter the names of the internal and external interfaces:
IFACE_LAN = eth0
IFACE_WAN = eth1
IMPORTANT: configuring routing, masquerade, etc. not a zapret task.
Only modes that intercept transit traffic are enabled.

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

Simple install works on most modern linux distributions with systemd.
Run install_easy.sh and answer its questions.

Simple install to openwrt
-------------------------

install_easy.sh also works on openwrt but there're additional challenges.
They are mainly about possibly low flash free space.
Simple install will not work if it has no space to install itself and required packages from the repo.

Another challenge would be to bring zapret to the router. You can download zip from github and use it.
Do not repack zip contents in the Windows, because this way you break chmod and links.
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


Https blocking bypass
----------------------

SOMETIMES (but not often) a tls handshake split trick works.
Try MODE=..._https
May be you're lucky.

MORE OFTEN DPI desync attack work, but it may require some manual tuning.

OTHERWISE you have to redirect traffic through a third-party host.
It is proposed to use transparent redirect through socks5 using iptables + redsocks, or iptables + iproute + vpn.
Redsocks variant is described in https.txt.
iproute + wireguard - in wireguard_iproute_openwrt.txt.
(they are russian)
