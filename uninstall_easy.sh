#!/bin/sh

# automated script for easy uninstalling zapret

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
IPSET_DIR="$EXEDIR/ipset"

GET_LIST_PREFIX=/ipset/get_
SYSTEMD_SYSTEM_DIR=/lib/systemd/system
[ -d "$SYSTEMD_SYSTEM_DIR" ] || SYSTEMD_SYSTEM_DIR=/usr/lib/systemd/system

exists()
{
	which $1 >/dev/null 2>/dev/null
}
whichq()
{
	which $1 2>/dev/null
}

exitp()
{
	echo
	echo press enter to continue
	read A
	exit $1
}

require_root()
{
	[ $(id -u) -ne "0" ] && {
		echo root is required
		exists sudo && exec sudo "$0"
		exists su && exec su -c "$0"
		echo su or sudo not found
		exitp 2
	}
}


check_system()
{
	echo \* checking system

	SYSTEM=""
	SYSTEMCTL=$(whichq systemctl)

	local UNAME=$(uname)
	if [ "$UNAME" = "Linux" ]; then
		if [ -x "$SYSTEMCTL" ] ; then
			SYSTEM=systemd
		elif [ -f "/etc/openwrt_release" ] && exists opkg && exists uci ; then
			SYSTEM=openwrt
		else
			echo system is not either systemd based or openwrt. check readme.txt for manual setup info.
			exitp 5
		fi
	elif [ "$UNAME" = "Darwin" ]; then
		SYSTEM=macos
	else
		echo easy installer only supports Linux and MacOS. check readme.txt for supported systems and manual setup info.
		exitp 5
	fi
	echo system is based on $SYSTEM
}


crontab_del()
{
	exists crontab || return

	echo \* removing crontab entry

	CRONTMP=/tmp/cron.tmp
	crontab -l >$CRONTMP 2>/dev/null
	if grep -q "$GET_LIST_PREFIX" $CRONTMP; then
		echo removing following entries from crontab :
		grep "$GET_LIST_PREFIX" $CRONTMP
		grep -v "$GET_LIST_PREFIX" $CRONTMP >$CRONTMP.2
		crontab $CRONTMP.2
		rm -f $CRONTMP.2
	fi
	rm -f $CRONTMP
}


service_stop_systemd()
{
	echo \* stopping zapret service

	"$SYSTEMCTL" daemon-reload
	"$SYSTEMCTL" disable zapret
	"$SYSTEMCTL" stop zapret
}

service_remove_systemd()
{
	echo \* removing zapret service

	rm -f "$SYSTEMD_SYSTEM_DIR/zapret.service"
	"$SYSTEMCTL" daemon-reload
}

timer_remove_systemd()
{
	echo \* removing zapret-list-update timer

	"$SYSTEMCTL" daemon-reload
	"$SYSTEMCTL" disable zapret-list-update.timer
	"$SYSTEMCTL" stop zapret-list-update.timer
	rm -f "$SYSTEMD_SYSTEM_DIR/zapret-list-update.service" "$SYSTEMD_SYSTEM_DIR/zapret-list-update.timer"
	"$SYSTEMCTL" daemon-reload
}



remove_systemd()
{
	INIT_SCRIPT=/etc/init.d/zapret
	
	service_stop_systemd
	service_remove_systemd
	timer_remove_systemd
	crontab_del
}





openwrt_fw_section_find()
{
	# $1 - fw include postfix
	# echoes section number
	
	i=0
	while true
	do
		path=$(uci -q get firewall.@include[$i].path)
		[ -n "$path" ] || break
		[ "$path" = "$OPENWRT_FW_INCLUDE$1" ] && {
	 		echo $i
	 		return 0
		}
		i=$(($i+1))
	done
	return 1
}
openwrt_fw_section_del()
{
	# $1 - fw include postfix

	local id=$(openwrt_fw_section_find $1)
	[ -n "$id" ] && {
		uci delete firewall.@include[$id] && uci commit firewall
		rm -f "$OPENWRT_FW_INCLUDE$1"
	}
}

remove_openwrt_firewall()
{
	echo \* removing firewall script
	
	openwrt_fw_section_del
	# from old zapret versions. now we use single include
	openwrt_fw_section_del 6

	# free some RAM
	"$IPSET_DIR/create_ipset.sh" clear
}

restart_openwrt_firewall()
{
	echo \* restarting firewall

	fw3 -q restart || {
		echo could not restart firewall
		exitp 30
	}
}

remove_openwrt_iface_hook()
{
	echo \* removing ifup hook
	
	rm -f /etc/hotplug.d/iface/??-zapret
}


service_remove_sysv()
{
	echo \* removing zapret service

	[ -x "$INIT_SCRIPT" ] && {
		"$INIT_SCRIPT" disable
		"$INIT_SCRIPT" stop
	}
	rm -f "$INIT_SCRIPT"
}

remove_openwrt()
{
	INIT_SCRIPT=/etc/init.d/zapret
	OPENWRT_FW_INCLUDE=/etc/firewall.zapret

	remove_openwrt_firewall
	restart_openwrt_firewall
	service_remove_sysv
	remove_openwrt_iface_hook
	crontab_del
}


service_remove_macos()
{
	echo \* removing zapret service

	rm -f /Library/LaunchDaemons/zapret.plist
	zapret_stop_daemons
}

remove_macos_firewall()
{
	echo \* removing zapret PF hooks

	pf_anchors_clear
	pf_anchors_del
	pf_anchor_root_del
	pf_anchor_root_reload
}

remove_macos()
{
	remove_macos_firewall
	service_remove_macos
	crontab_del
}


check_system
require_root

[ "$SYSTEM" = "macos" ] && . "$EXEDIR/init.d/macos/functions"

case $SYSTEM in
	systemd)
		remove_systemd
		;;
	openwrt)
		remove_openwrt
		;;
	macos)
		remove_macos
		;;
esac


exitp 0
