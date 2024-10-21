Minimal tpws startup script for low storage openwrt.

--- openwrt with NFTABLES (22+)

Make sure you are running openwrt with nftables, not iptables.
No opkg dependencies required !

* install :

Copy everything from tpws directory to the root of the router.
Copy tpws binary for your architecture to /usr/bin/tpws
Set proper access rights : chmod 755 /etc/init.d/tpws /usr/bin/tpws
EDIT /etc/config/tpws
If you don't want ipv6 : edit /etc/nftables.d and comment lines with ipv6 redirect
/etc/init.d/tpws enable
/etc/init.d/tpws start
fw4 restart

* full uninstall :

/etc/init.d/tpws disable
/etc/init.d/tpws stop
rm -f /etc/nftables.d/90-tpws.nft /etc/firewall.user /etc/init.d/tpws
fw4 restart

--- openwrt with IPTABLES (21-)

Make sure you are running openwrt with iptables, not nftables.
Make sure you do not have anything valuable in /etc/firewall.user.
If you have - do not blindly follow instruction in firewall.user part.
Merge the code instead or setup your own firewall include in /etc/config/firewall.

opkg update
opkg install iptables-mod-extra
IPV6 ONLY : opkg install ip6tables-mod-nat

* install :

Copy everything from tpws directory to the root of the router.
Copy tpws binary for your architecture to /usr/bin/tpws
Set proper access rights : chmod 755 /etc/init.d/tpws /usr/bin/tpws
EDIT /etc/config/tpws
If you don't want ipv6 : edit /etc/firewall.user and set DISABLE_IPV6=1
/etc/init.d/tpws enable
/etc/init.d/tpws start
fw3 restart

* full uninstall :

/etc/init.d/tpws disable
/etc/init.d/tpws stop
rm -f /etc/nftables.d/90-tpws.nft /etc/firewall.user /etc/init.d/tpws
touch /etc/firewall.user
fw3 restart
