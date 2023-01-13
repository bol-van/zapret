#!/bin/sh

[ "$type" == "ip6tables" ] && exit 0
[ "$table" != "mangle" ] && exit 0

SCRIPT=$(readlink /opt/etc/init.d/S99zapret)
if [ -n "$SCRIPT" ]; then
	EXEDIR=$(dirname "$SCRIPT")
	ZAPRET_BASE=$(readlink -f "$EXEDIR/../..")
else
	ZAPRET_BASE=/opt/zapret
fi

. "$EXEDIR/functions"

case $MODE in
	nfqws|twps|custom)
		zapret_apply_firewall
	;;
esac
