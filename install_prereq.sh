#!/bin/sh

# install prerequisites

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
ZAPRET_CONFIG="$EXEDIR/config"
ZAPRET_BASE="$EXEDIR"

. "$ZAPRET_CONFIG"
. "$ZAPRET_BASE/common/base.sh"
. "$ZAPRET_BASE/common/elevate.sh"
. "$ZAPRET_BASE/common/fwtype.sh"
. "$ZAPRET_BASE/common/dialog.sh"
. "$ZAPRET_BASE/common/installer.sh"
. "$ZAPRET_BASE/common/ipt.sh"

select_ipv6()
{
	local T=N

	[ "$DISABLE_IPV6" != '1' ] && T=Y
	local old6=$DISABLE_IPV6
	echo
	if ask_yes_no $T "enable ipv6 support"; then
		DISABLE_IPV6=0
	else
		DISABLE_IPV6=1
	fi
	[ "$old6" != "$DISABLE_IPV6" ] && write_config_var DISABLE_IPV6
}
select_fwtype()
{
	echo
	[ $(get_ram_mb) -le 400 ] && {
		echo WARNING ! you are running a low RAM system
		echo WARNING ! nft requires lots of RAM to load huge ip sets, much more than ipsets require
		echo WARNING ! if you need large lists it may be necessary to fall back to iptables+ipset firewall
	}
	echo select firewall type :
	ask_list FWTYPE "iptables nftables" "$FWTYPE" && write_config_var FWTYPE
}

ask_config()
{
	[ "$SYSTEM" = openwrt ] && select_ipv6
	select_fwtype
}


# build binaries, do not use precompiled
[ "$1" = "make" ] && FORCE_BUILD=1

umask 0022
fsleep_setup
fix_sbin_path
check_system
require_root
ask_config

case $UNAME in
	Linux)
		case $SYSTEM in
			openwrt)
				check_prerequisites_openwrt
				;;
			*)
				check_prerequisites_linux
				;;
		esac
		;;
esac


exitp 0
