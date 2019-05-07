#!/bin/sh

# automated script for easy uninstalling zapret

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)
GET_IPLIST_PREFIX=/ipset/get_

exists()
{
	which $1 >/dev/null 2>/dev/null
}
whichq()
{
	which $1 2>/dev/null
}

[ $(id -u) -ne "0" ] && {
	echo root is required
	exists sudo && exec sudo $0
	exists su && exec su -c $0
	echo su or sudo not found
	exit 2
}

exitp()
{
	echo
	echo press enter to continue
	read A
	exit $1
}

md5file()
{
	md5sum "$1" | cut -f1 -d ' '
}


check_system()
{
	echo \* checking system ...

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


service_stop_systemd()
{
	echo \* stopping service and unregistering init script

	"$SYSTEMCTL" disable zapret
	"$SYSTEMCTL" stop zapret
}

remove_sysv_init()
{
	echo \* removing init script ...

	script_mode=Y
	[ -f "$INIT_SCRIPT" ] &&
	{
		[ $(md5file "$INIT_SCRIPT") = $(md5file "$INIT_SCRIPT_SRC") ] ||
		{
			echo $INIT_SCRIPT already exists and differs from $INIT_SCRIPT_SRC
			echo Y = remove it
			echo L = leave it
			read script_mode
		}
		if [ "$script_mode" = "Y" ] || [ "$script_mode" = "y" ]; then
			rm -vf $INIT_SCRIPT
		fi
	}
}

cleanup_systemd()
{
	echo \* systemd cleanup ...

	"$SYSTEMCTL" daemon-reload
}

crontab_del()
{
	echo \* removing crontab entry ...

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


remove_systemd()
{
	INIT_SCRIPT_SRC=$EXEDIR/init.d/sysv/zapret
	INIT_SCRIPT=/etc/init.d/zapret
	
	service_stop_systemd
	remove_sysv_init
	cleanup_systemd
	crontab_del
}



openwrt_fw_section_find()
{
	# echoes section number
	
	i=0
	while true
	do
		path=$(uci -q get firewall.@include[$i].path)
		[ -n "$path" ] || break
		[ "$path" == "$OPENWRT_FW_INCLUDE" ] && {
	 		echo $i
		 	true
	 		return
		}
		i=`expr $i + 1`
	done
	false
	return
}
openwrt_fw_section_del()
{
	local id=$(openwrt_fw_section_find)
	[ -n "$id" ] && {
		uci delete firewall.@include[$id] && uci commit firewall
	}
}

remove_openwrt_firewall()
{
	echo \* removing firewall script ...
	
	openwrt_fw_section_del
	[ -f "$OPENWRT_FW_INCLUDE" ] && rm -f "$OPENWRT_FW_INCLUDE"
}

restart_openwrt_firewall()
{
	echo \* restarting firewall ...

	fw3 -q restart || {
		echo could not restart firewall
		exitp 30
	}
}


service_remove_sysv()
{
	echo \* removing zapret service ...

	[ -x "$INIT_SCRIPT" ] && {
		"$INIT_SCRIPT" disable
		"$INIT_SCRIPT" stop
	}
	[ -f "$INIT_SCRIPT" ] && rm -f "$INIT_SCRIPT"
}

remove_openwrt()
{
	INIT_SCRIPT_SRC=$EXEDIR/init.d/openwrt/zapret
	INIT_SCRIPT=/etc/init.d/zapret
	OPENWRT_FW_INCLUDE=/etc/firewall.zapret

	remove_openwrt_firewall
	restart_openwrt_firewall
	service_remove_sysv
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
