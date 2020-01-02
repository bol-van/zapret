#!/bin/sh

# automated script for easy uninstalling zapret

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")
GET_IPLIST_PREFIX=/ipset/get_
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

[ $(id -u) -ne "0" ] && {
	echo root is required
	exists sudo && exec sudo "$0"
	exists su && exec su -c "$0"
	echo su or sudo not found
	exitp 2
}

md5file()
{
	md5sum "$1" | cut -f1 -d ' '
}


check_system()
{
	echo \* checking system

	SYSTEM=""
	SYSTEMCTL=$(whichq systemctl)

	if [ -x "$SYSTEMCTL" ] ; then
		SYSTEM=systemd
	elif [ -f "/etc/openwrt_release" ] && exists opkg && exists uci ; then
		SYSTEM=openwrt
	else
		echo system is not either systemd based or openwrt
		exitp 5
	fi
	echo system is based on $SYSTEM
}


crontab_del()
{
	exists crontab || return

	echo \* removing crontab entry

	CRONTMP=/tmp/cron.tmp
	crontab -l >$CRONTMP
	if grep -q "$GET_IPLIST_PREFIX" $CRONTMP; then
		echo removing following entries from crontab :
		grep "$GET_IPLIST_PREFIX" $CRONTMP
		grep -v "$GET_IPLIST_PREFIX" $CRONTMP >$CRONTMP.2
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
	 		return
		}
		i=$(($i+1))
	done
	false
	return
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



check_system

case $SYSTEM in
	systemd)
		remove_systemd
		;;
	openwrt)
		remove_openwrt
		;;
esac


exitp 0
