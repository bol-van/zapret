#!/bin/sh

# automated script for easy installing zapret

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)
ZAPRET_BASE=/opt/zapret
ZAPRET_CONFIG=$EXEDIR/config

. "$ZAPRET_CONFIG"

SYSTEMD_SYSV_GENERATOR=/lib/systemd/system-generators/systemd-sysv-generator
SYSTEMD_SYSV_GENERATOR2=/usr$SYSTEMD_SYSV_GENERATOR

[ -n "$GETLIST" ] && GET_LIST="$EXEDIR/ipset/$GETLIST"
GET_LIST_PREFIX=/ipset/get_

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

get_dir_inode()
{
	ls -id "$1" | cut -f1 -d ' '
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
		[ -x "$SYSTEMD_SYSV_GENERATOR" ] || [ -x "$SYSTEMD_SYSV_GENERATOR2" ] || {
			echo systemd is present but it does not support sysvinit compatibility
			echo $SYSTEMD_SYSV_GENERATOR is required
			exitp 5
		}
		SYSTEM=systemd
	elif [ -f "/etc/openwrt_release" ] && exists opkg && exists uci ; then
		SYSTEM=openwrt
	else
		echo system is not either systemd based or openwrt
		exitp 5
	fi
	echo system is based on $SYSTEM
}

call_install_bin()
{
	"$EXEDIR/install_bin.sh" $1 || {
		echo binaries compatible with your system not found
		exitp 8
	}
}

install_binaries()
{
	echo \* installing binaries ...

	call_install_bin
}

get_bin_arch()
{
	call_install_bin getarch
}


copy_all()
{
	cp -R "$1" "$2"
}
copy_minimal()
{
	local ARCH=$(get_bin_arch)
	local BINDIR="$1/binaries/$ARCH"
	
	[ -d "$2" ] || mkdir -p "$2"
	
	mkdir "$2/tpws" "$2/nfq" "$2/ip2net" "$2/mdig" "$2/binaries" "$2/binaries/$ARCH"
	cp -R "$1/ipset" "$2"
	cp -R "$1/init.d" "$2"
	cp "$1/install_easy.sh" "$1/uninstall_easy.sh" "$1/install_bin.sh" "$2"
	cp "$BINDIR/tpws" "$BINDIR/nfqws" "$BINDIR/ip2net" "$BINDIR/mdig" "$2/binaries/$ARCH"
}

check_location()
{
	# $1 - copy function

	echo \* checking location ...

	# use inodes in case something is linked
	[ -d "$ZAPRET_BASE" ] && [ $(get_dir_inode "$EXEDIR") = $(get_dir_inode "$ZAPRET_BASE") ] || {
		echo easy install is supported only from default location : $ZAPRET_BASE
		echo currenlty its run from $EXEDIR
		echo -n "do you want the installer to copy it for you (Y/N) ? "
		read A
		if [ "$A" = "Y" ] || [ "$A" = "y" ]; then
			if [ -d "$ZAPRET_BASE" ]; then
				echo installer found existing $ZAPRET_BASE
				echo -n "do you want to delete all files there and copy this version (Y/N) ? "
				read A
				if [ "$A" = "Y" ] || [ "$A" = "y" ]; then
					rm -r "$ZAPRET_BASE"
				else
					echo refused to overwrite $ZAPRET_BASE. exiting
					exitp 3
				fi
			fi
			$1 "$EXEDIR" "$ZAPRET_BASE"
			echo relaunching itself from $ZAPRET_BASE
			exec $ZAPRET_BASE/$(basename $0)
		else
			echo copying aborted. exiting
			exitp 3
		fi
	}
	echo running from $EXEDIR
}


crontab_add()
{
	[ -x "$GET_LIST" ] &&	{
		echo \* adding crontab entry ...

		CRONTMP=/tmp/cron.tmp
		crontab -l >$CRONTMP
		if grep -q "$GET_LIST_PREFIX" $CRONTMP; then
			echo some entries already exist in crontab. check if this is corrent :
			grep "$GET_LIST_PREFIX" $CRONTMP
		else
			echo "0 12 * * */2 $GET_LIST" >>$CRONTMP
			crontab $CRONTMP
		fi

		rm -f $CRONTMP
	}
}

check_preprequisites_linux()
{
	echo \* checking prerequisites ...

	if exists ipset && exists curl ; then
		echo everything is present
	else
		echo \* installing prerequisites ...

		APTGET=$(whichq apt-get)
		YUM=$(whichq yum)
		PACMAN=$(whichq pacman)
		ZYPPER=$(whichq zypper)
			if [ -x "$APTGET" ] ; then
				"$APTGET" update
				"$APTGET" install -y --no-install-recommends ipset curl dnsutils || {
					echo could not install prerequisites
					exitp 6
				}
			elif [ -x "$YUM" ] ; then
			"$YUM" -y install curl ipset daemonize || {
				echo could not install prerequisites
				exitp 6
			}
		elif [ -x "$PACMAN" ] ; then
			"$PACMAN" -Syy
			"$PACMAN" --noconfirm -S ipset curl || {
				echo could not install prerequisites
				exitp 6
			}
		elif [ -x "$ZYPPER" ] ; then
			"$ZYPPER" --non-interactive install ipset curl || {
				echo could not install prerequisites
				exitp 6
			}
		else
			echo supported package manager not found
			echo you must manually install : ipset curl
			exitp 5
		fi
	fi
}

install_sysv_init()
{
	echo \* installing init script ...

	[ -x "$INIT_SCRIPT" ] && "$INIT_SCRIPT" stop

	script_mode=Y
	[ -f "$INIT_SCRIPT" ] &&
	{
		[ $(md5file "$INIT_SCRIPT") = $(md5file "$INIT_SCRIPT_SRC") ] ||
		{
			echo $INIT_SCRIPT already exists and differs from $INIT_SCRIPT_SRC
			echo Y = overwrite with new version 
			echo N = exit
			echo L = leave current version and continue
			read script_mode
			case "${script_mode}" in
				Y|y|L|l)
					;;
				*)
					echo aborted
					exitp 3
					;;
			esac
		}
	}

	if [ "$script_mode" = "Y" ] || [ "$script_mode" = "y" ]; then
		echo "copying : $INIT_SCRIPT_SRC => $INIT_SCRIPT"
		cp -f $INIT_SCRIPT_SRC $INIT_SCRIPT
	fi
}

register_sysv_init_systemd()
{
	echo \* registering init script ...

	"$SYSTEMCTL" daemon-reload
	"$SYSTEMCTL" enable zapret || {
		echo could not register $INIT_SCRIPT with systemd
		exitp 20
	}
}

service_stop_systemd()
{
	echo \* stopping service and unregistering init script

	"$SYSTEMCTL" disable zapret
	"$SYSTEMCTL" stop zapret
}


download_list()
{
	[ -x "$GET_LIST" ] &&	{
		echo \* downloading blocked ip/host list ...

		rm -f "$EXEDIR/ipset/zapret-ip.txt" "$EXEDIR/ipset/zapret-ip-user.txt" \
			"$EXEDIR/ipset/zapret-ip-ipban.txt" "$EXEDIR/ipset/zapret-ip-user-ipban.txt" \
			"$EXEDIR/ipset/zapret-hosts.txt"
		"$GET_LIST" || {
			echo could not download ip list
			exitp 25
		}
	}
}

service_start_systemd()
{
	echo \* starting zapret service ...

	systemctl start zapret || {
		echo could not start zapret service
		exitp 30
	}
}

install_systemd()
{
	INIT_SCRIPT_SRC=$EXEDIR/init.d/sysv/zapret
	INIT_SCRIPT=/etc/init.d/zapret

	check_location copy_all
	check_preprequisites_linux
	service_stop_systemd	
	install_binaries
	install_sysv_init
	register_sysv_init_systemd
	download_list
	crontab_add
	service_start_systemd
}





check_kmod()
{
	[ -f "/lib/modules/$(uname -r)/$1.ko" ]
}
check_package_exists_openwrt()
{
	[ -n "opkg list $1" ]
}
check_package_openwrt()
{
	[ -n "$(opkg list-installed $1)" ]
}
check_packages_openwrt()
{
	for pkg in $@; do
		check_package_openwrt $pkg || return
	done
}

check_preprequisites_openwrt()
{
	echo \* checking prerequisites ...
	
	local PKGS="iptables-mod-extra iptables-mod-nfqueue iptables-mod-filter iptables-mod-ipopt ipset curl"
	
	# in recent lede/openwrt iptable_raw in separate package
	if check_kmod iptable_raw && check_packages_openwrt $PKGS ; then
		echo everything is present
	else
		echo \* installing prerequisites ...
		
		opkg update
		if check_package_exists_openwrt kmod-ipt-raw ; then PKGS="$PKGS kmod-ipt-raw" ; fi
		opkg install $PKGS || {
			echo could not install prerequisites
			exitp 6
		}
	fi
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
	 let i=i+1
	done
	false
	return
}
openwrt_fw_section_add()
{
	# echoes section number
	
	openwrt_fw_section_find ||
	{
		uci add firewall include >/dev/null || return
		echo -1
		true
	}
}
openwrt_fw_section_del()
{
	local id=$(openwrt_fw_section_find)
	[ -n "$id" ] && {
		uci delete firewall.@include[$id] && uci commit firewall
	}
}
openwrt_fw_section_configure()
{
	local id=$(openwrt_fw_section_add)
	[ -z "$id" ] ||
	 ! uci set firewall.@include[$id].path="$OPENWRT_FW_INCLUDE" ||
	 ! uci set firewall.@include[$id].reload="1" ||
	 ! uci commit firewall &&
	{
		echo could not add firewall include
		exitp 50
	}
}

install_openwrt_firewall()
{
	echo \* installing firewall script ...
	
	[ -n "MODE" ] || {
		echo should specify MODE in $ZAPRET_CONFIG
		exitp 7
	}
	
	local FW_SCRIPT_SRC="$FW_SCRIPT_SRC_DIR.$MODE"
	[ -f "$FW_SCRIPT_SRC" ] || {
		echo firewall script $FW_SCRIPT_SRC not found. removing firewall include
		openwrt_fw_section_del
		return
	}
	echo "copying : $FW_SCRIPT_SRC => $OPENWRT_FW_INCLUDE"
	cp -f "$FW_SCRIPT_SRC" "$OPENWRT_FW_INCLUDE"
	
	openwrt_fw_section_configure
}

restart_openwrt_firewall()
{
	echo \* restarting firewall ...

	fw3 -q restart || {
		echo could not restart firewall
		exitp 30
	}
}

register_sysv_init()
{
	echo \* registering init script ...
	
	"$INIT_SCRIPT" enable
}

service_start_sysv()
{
	echo \* starting zapret service ...

	"$INIT_SCRIPT" start || {
		echo could not start zapret service
		exitp 30
	}
}



install_openwrt()
{
	INIT_SCRIPT_SRC=$EXEDIR/init.d/openwrt/zapret
	INIT_SCRIPT=/etc/init.d/zapret
	FW_SCRIPT_SRC_DIR=$EXEDIR/init.d/openwrt/firewall.zapret
	OPENWRT_FW_INCLUDE=/etc/firewall.zapret
	
	check_location copy_minimal
	check_preprequisites_openwrt
	install_binaries
	install_sysv_init
	register_sysv_init
	download_list
	crontab_add
	service_start_sysv
	install_openwrt_firewall
	restart_openwrt_firewall
}



check_system

case $SYSTEM in
	systemd)
		install_systemd
		;;
	openwrt)
		install_openwrt
		;;
esac


exitp 0
