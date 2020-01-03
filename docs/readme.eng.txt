What is it for
--------------

Bypass the blocking of web sites http.
The project is mainly aimed at the Russian audience to fight russian regulator named "Roskomnadzor".
Some features of the project are russian reality specific (such as getting list of sites
blocked by Roskomnadzor), but most others are common.

How it works
------------

DPI providers have gaps. They happen because DPI rules are writtten for
ordinary user programs, omitting all possible cases that are permissible by standards.
This is done for simplicity and speed. It makes no sense to catch 0.01% hackers,
because these blockings are quite simple and easily bypassed even by ordinary users.

Some DPIs cannot recognize the http request if it is divided into TCP segments.
For example, a request of the form "GET / HTTP / 1.1 \ r \ nHost: kinozal.tv ......"
we send in 2 parts: first go "GET", then "/ HTTP / 1.1 \ r \ nHost: kinozal.tv .....".
Other DPIs stumble when the "Host:" header is written in another case: for example, "host:".
Sometimes work adding extra space after the method: "GET /" => "GET  /"
or adding a dot at the end of the host name: "Host: kinozal.tv."


How to put this into practice in the linux system
-------------------------------------------------

How to make the system break the request into parts? You can pipe the entire TCP session
through transparent proxy, or you can replace the tcp window size field on the first incoming TCP packet with a SYN, ACK.
Then the client will think that the server has set a small window size for it and the first data segment
will send no more than the specified length. In subsequent packages, we will not change anything.
The further behavior of the system depends on the implemented algorithm in the OS.
Experience shows that linux always sends first packet no more than the specified
in window size length, the rest of the packets until some time sends no more than max (36, specified_size).
After a number of packets, the window scaling mechanism is triggered and starts taking
the scaling factor into account. The packet size becomes no more than max (36, specified_ramer << scale_factor).
The behavior is not very elegant, but since we do not affect the size of the incoming packets,
and the amount of data received in http is usually much higher than the amount sent, then visually
there will be only small delays.
Windows behaves in a similar case much more predictably. First segment
the specified length goes away, then the window size changes depending on the value,
sent in new tcp packets. That is, the speed is almost immediately restored to the possible maximum.

Its easy to intercept a packet with SYN, ACK using iptables.
However, the options for editing packets in iptables are severely limited.
It’s not possible to change window size with standard modules.
For this, we will use the NFQUEUE. This tool allows transfer packets to the processes running in user mode.
The process, accepting a packet, can change it, which is what we need.

iptables -t mangle -I PREROUTING -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 200 --queue-bypass

It will queue the packets we need to the process that listens on the queue with the number 200.
Process will replace the window size. PREROUTING will catch packets addressed to the host itself and routed packets.
That is, the solution works the same way as on the client, so on the router. On a PC-based or OpenWRT router.
In principle, this is enough.
However, with such an impact on TCP there will be a slight delay.
In order not to touch the hosts that are not blocked by the provider, you can make such a move.
Create a list of blocked domains, resolve them to IP addresses and save to ipset named "zapret".
Add to rule:

iptables -t mangle -I PREROUTING -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -m set --match-set zapret src -j NFQUEUE --queue-num 200 --queue-bypass

Thus, the impact will be made only on ip addresses related to blocked sites.
The list can be updated in scheduled task every few days.

If DPI cant be bypassed with splitting a request into segments, then sometimes helps changing case
of the "Host:" http header. We may not need a window size replacement, so the do not need PREROUTING chain.
Instead, we hang on outgoing packets in the POSTROUTING chain:

iptables -t mangle -I POSTROUTING -p tcp --dport 80 -m set --match-set zapret dst -j NFQUEUE --queue-num 200 --queue-bypass

In this case, additional points are also possible. DPI can catch only the first http request, ignoring
subsequent requests in the keep-alive session. Then we can reduce the cpu load abandoning the processing of unnecessary packages.

iptables -t mangle -I POSTROUTING -p tcp --dport 80 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:5 -m set --match-set zapret dst -j NFQUEUE --queue-num 200 --queue-bypass

It happens that the provider monitors the entire HTTP session with keep-alive requests. In this case
it is not enough to restrict the TCP window when establishing a connection. Each http request must be splitted
to multiple TCP segments. This task is solved through the full proxying of traffic using
transparent proxy (TPROXY or DNAT). TPROXY does not work with connections originating from the local system
so this solution is applicable only on the router. DNAT works with local connections,
but there is a danger of entering into endless recursion, so the daemon is launched as a separate user,
and for this user, DNAT is disabled via "-m owner". Full proxying requires more resources than outbound packet
manipulation without reconstructing a TCP connection.

iptables -t nat -I PREROUTING -p tcp --dport 80 -j DNAT --to 127.0.0.1:1188
iptables -t nat -I OUTPUT -p tcp --dport 80 -m owner ! --uid-owner tpws -j DNAT --to 127.0.0.1:1188

NOTE: DNAT on localhost works in the OUTPUT chain, but does not work in the PREROUTING chain without enabling the route_localnet parameter:

sysctl -w net.ipv4.conf.<incoming_interface_name>.route_localnet=1

You can use "-j REDIRECT --to-port 1188" instead of DNAT, but in this case the transpareny proxy process
should listen on the ip address of the incoming interface or on all addresses. Listen all - not good
in terms of security. Listening one (local) is possible, but in the case of automated
script will have to recognize it, then dynamically enter it into the command. In any case, additional efforts are required.

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
 --wsize=<window_size> 			; set window size. 0 = do not modify
 --hostcase           			; change Host: => host:
 --hostspell=HoSt      			; exact spelling of the "Host" header. must be 4 chars. default is "host"
 --hostnospace         			; remove space after Host: and add it to User-Agent: to preserve packet size
 --daemon              			; daemonize
 --pidfile=<filename>  			; write pid to file
 --user=<username>      		; drop root privs
 --uid=uid[:gid]			; drop root privs
 --dpi-desync[=<mode>]			; try to desync dpi state. modes : fake rst rstack disorder disorder2
 --dpi-desync-fwmark=<int|0xHEX>        ; override fwmark for desync packet. default = 0x40000000
 --dpi-desync-ttl=<int>                 ; set ttl for desync packet
 --dpi-desync-fooling=none|md5sig|badsum
 --dpi-desync-retrans=0|1               ; (fake,rst,rstack only) 0(default)=reinject original data packet after fake  1=drop original data packet to force its retransmission
 --dpi-desync-skip-nosni=0|1		; 1(default)=do not apply desync to requests without hostname in the SNI
 --dpi-desync-split-pos=<1..1500>	; (for disorder only) split TCP packet at specified position
 --hostlist=<filename>                  ; apply dpi desync only to the listed hosts (one host per line, subdomains auto apply)

The manipulation parameters can be combined in any way.

COMMENT. As described earlier, Linux behaves strangely when the window size is changed, unlike Windows.
Following segments do not restore their full length. Connection can go for a long time in batches of small packets.
Package modification parameters (--hostcase, ...) may not work, because nfqws does not work with the connection,
but only with separate packets in which the search may not be found, because scattered across multiple packets.
If the source of the packages is Windows, there is no such problem.

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
* TTL looks like the best option, but it requires special tuning for earch ISP. If DPI is further than local ISP websites
  you can cut access to them. Manual IP exclude list is required. Its possible to use md5sig with ttl.
  This way you cant hurt anything, but good chances it will help to open local ISP websites.
  If automatic solution cannot be found then use zapret-hosts-user-exclude.txt.

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
Mode 'disorder2' disables sending of fake segments. It can be used as a faster alternative to --wsize.

Hostlist is applicable only to desync attack. It does not work for other options.
Hosts are extracted from plain http request Host: header and SNI of ClientHelllo TLS message.
Subdomains are applied automatically. gzip lists are supported.

iptables for performing the attack :

iptables -t mangle -I POSTROUTING -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 2:4 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 200 --queue-bypass

connbytes will only queue the first data packet. mark is needed to keep away generated packets from NFQUEUE.
nfqws sets fwmark when it sends generated packets.

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

nfqws_ipset - use nfqws for http. targets are filtered by ipset "zapret"
nfqws_ipset_https - use nfqws for http and https. targets are filtered by ipset "zapret"
nfqws_all - use nfqws for all http
nfqws_all_https - use nfqws for all http and https
nfqws_all_desync - use nfqws for DPI desync attack on http и https for all http and https
nfqws_ipset_desync - use nfqws for DPI desync attack on http и https for all http and https. targets are filtered by ipset "zapret"
nfqws_hostlist_desync - use nfqws for DPI desync attack on http и https , only to hosts from hostlist

tpws_ipset - use tpws for http. targets are filtered by ipset "zapret"
tpws_ipset_https - use tpws for http and https. targets are filtered by ipset "zapret"
tpws_all - use tpws for all http
tpws_all_https - use tpws for all http and https
tpws_hostlist - same as tpws_all but touch only domains from the hostlist

ipset - only fill ipset. futher actions depend on your own code

Its possible to change manipulation options used by the daemons :

NFQWS_OPT="--wsize=3 --hostspell=HOST"
TPWS_OPT_HTTP="--hostspell=HOST --split-http-req=method"
TPWS_OPT_HTTPS="--split-pos=3"

Options for DPI desync attack are configured separately:

DESYNC_MARK=0x40000000
NFQWS_OPT_DESYNC="--dpi-desync --dpi-desync-ttl=0 --dpi-desync-fooling=badsum --dpi-desync-fwmark=$DESYNC_MARK"


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

As a rule, DPI tricks do not help to bypass https blocking.
You have to redirect traffic through a third-party host.
It is proposed to use transparent redirect through socks5 using iptables + redsocks, or iptables + iproute + vpn.
Redsocks variant is described in https.txt.
iproute + wireguard - in wireguard_iproute_openwrt.txt.
(they are russian)

SOMETIMES (but not often) a tls handshake split trick works.
Try MODE=..._https
May be you're lucky.

MORE OFTEN DPI desync attack work, but it may require some manual tuning.
