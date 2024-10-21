Minimal tpws startup script for low storage openwrt with nftables.
No opkg dependencies required !

* install :

Make sure you are running openwrt with nftables, not iptables.
Copy everything from tpws directory to the root of the router.
Copy tpws binary for your architecture to /usr/bin/tpws
Set proper access rights : chmod 755 /etc/init.d/tpws /usr/bin/tpws
EDIT /etc/config/tpws
/etc/init.d/tpws enable
/etc/init.d/tpws start
fw4 reload

* full uninstall :

/etc/init.d/tpws disable
/etc/init.d/tpws stop
rm -f /etc/nftables.d/90-tpws.nft /etc/init.d/tpws
fw4 restart
