#!/bin/sh

# automated script for easy installing zapret

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")
ZAPRET_BASE=/opt/zapret
ZAPRET_CONFIG=$EXEDIR/config

. "$ZAPRET_CONFIG"

GET_LIST="$EXEDIR/ipset/get_config.sh"
GET_LIST_PREFIX=/ipset/get_
INIT_SCRIPT=/etc/init.d/zapret

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

get_dir_inode()
{
	ls -id "$1" | awk '{print $1}'
}

md5file()
{
	md5sum "$1" | cut -f1 -d ' '
}

random()
{
	# $1 - min, $2 - max
	local r rs
	if [ -c /dev/urandom ]; then
		read rs </dev/urandom
	else
		rs="$RANDOM$RANDOM$(date)"
	fi
	# shells use signed int64
	r=1$(echo $rs | md5sum | sed 's/[^0-9]//g' | head -c 17)
	echo $(( ($r % ($2-$1+1)) + $1 ))
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

call_install_bin()
{
	"$EXEDIR/install_bin.sh" $1 || {
		echo binaries compatible with your system not found
		exitp 8
	}
}
get_bin_arch()
{
	call_install_bin getarch
}

install_binaries()
{
	echo \* installing binaries

	call_install_bin
}

find_str_in_list()
{
	[ -n "$1" ] && {
		for v in $2; do
			[ "$v" = "$1" ] && return
		done
	}
	false
}

ask_list()
{
	# $1 - mode var
	# $2 - space separated value list
	# $3 - (optional) default value
	local M_DEFAULT
	eval M_DEFAULT="\$$1"
	local M_ALL=$M_DEFAULT
	local M=""
	
	[ -n "$3" ] && find_str_in_list "$M_DEFAULT" "$2" || M_DEFAULT="$3"
	
	n=1
	for m in $2; do
		echo $n : $m
		n=$(($n+1))
	done
	echo -n "your choice (default : $M_DEFAULT) : "
	read m
	[ -n "$m" ] && M=$(echo $2 | cut -d ' ' -f$m 2>/dev/null)
	[ -z "$M" ] && M="$M_DEFAULT"
	echo selected : $M
	eval $1="$M"
	
	[ "$M" != "$M_OLD" ]
}

write_config_var()
{
	# $1 - mode var
	local M
	eval M="\$$1"
	
	if [ -n "$M" ]; then
		sed -ri "s/^#?$1=.*$/$1=$M/" "$EXEDIR/config"
	else
		# write with comment at the beginning
		sed -ri "s/^#?$1=.*$/#$1=/" "$EXEDIR/config"
	fi
}
select_mode()
{
	echo select MODE :
	ask_list MODE "tpws_ipset tpws_ipset_https tpws_all tpws_all_https tpws_hostlist nfqws_ipset nfqws_ipset_https nfqws_all nfqws_all_https ipset" tpws_ipset_https && write_config_var MODE
}
select_getlist()
{
	if [ "${MODE%hostlist*}" != "$MODE" ] || [ "${MODE%ipset*}" != "$MODE" ]; then
		echo -n "do you want to auto download ip/host list (Y/N) ? "
		read A
		if [ "$A" != 'N' ] && [ "$A" != 'n' ]; then
			if [ "${MODE%hostlist*}" != "$MODE" ] ; then
				local GL_OLD=$GETLIST
				GETLIST="get_hostlist.sh"
				[ "$GL_OLD" != "$GET_LIST" ] && write_config_var GETLIST
			else
				GETLISTS="get_user.sh get_antizapret.sh get_combined.sh get_reestr.sh"
				GETLIST_DEF="get_antizapret.sh"
				ask_list GETLIST "$GETLISTS" "$GETLIST_DEF" && write_config_var GETLIST
			fi
			return
		fi
	fi
	GETLIST=""
	write_config_var GETLIST
}

ask_config()
{
	select_mode
	select_getlist
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
	cp "$1/config" "$1/install_easy.sh" "$1/uninstall_easy.sh" "$1/install_bin.sh" "$2"
	cp "$BINDIR/tpws" "$BINDIR/nfqws" "$BINDIR/ip2net" "$BINDIR/mdig" "$2/binaries/$ARCH"
}

check_location()
{
	# $1 - copy function

	echo \* checking location

	# use inodes in case something is linked
	[ -d "$ZAPRET_BASE" ] && [ $(get_dir_inode "$EXEDIR") = $(get_dir_inode "$ZAPRET_BASE") ] || {
		echo easy install is supported only from default location : $ZAPRET_BASE
		echo currently its run from $EXEDIR
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
	# $1 - hour min
	# $2 - hour max
	[ -x "$GET_LIST" ] &&	{
		echo \* adding crontab entry

		CRONTMP=/tmp/cron.tmp
		crontab -l >$CRONTMP
		if grep -q "$GET_LIST_PREFIX" $CRONTMP; then
			echo some entries already exist in crontab. check if this is corrent :
			grep "$GET_LIST_PREFIX" $CRONTMP
		else
			echo "$(random 0 59) $(random $1 $2) */2 * * $GET_LIST" >>$CRONTMP
			crontab $CRONTMP
		fi

		rm -f $CRONTMP
	}
}

check_prerequisites_linux()
{
	echo \* checking prerequisites

	# arch linux can miss cron
	if exists ipset && exists curl && exists crontab ; then
		echo everything is present
	else
		echo \* installing prerequisites

		APTGET=$(whichq apt-get)
		YUM=$(whichq yum)
		PACMAN=$(whichq pacman)
		ZYPPER=$(whichq zypper)
		if [ -x "$APTGET" ] ; then
			"$APTGET" update
			"$APTGET" install -y --no-install-recommends ipset curl dnsutils cron || {
				echo could not install prerequisites
				exitp 6
			}
		elif [ -x "$YUM" ] ; then
			"$YUM" -y install curl ipset cronie || {
				echo could not install prerequisites
				exitp 6
			}
		elif [ -x "$PACMAN" ] ; then
			"$PACMAN" -Syy
			"$PACMAN" --noconfirm -S ipset curl cronie || {
				echo could not install prerequisites
				exitp 6
			}
		elif [ -x "$ZYPPER" ] ; then
			"$ZYPPER" --non-interactive install ipset curl cron || {
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


service_install_systemd()
{
	echo \* installing zapret service

	[ -f "$INIT_SCRIPT" ] && rm -f "$INIT_SCRIPT"
	ln -fs "$EXEDIR/init.d/systemd/zapret.service" "$SYSTEMD_SYSTEM_DIR"
	"$SYSTEMCTL" daemon-reload
	"$SYSTEMCTL" enable zapret || {
		echo could not enable systemd service
		exitp 20
	}
}

service_stop_systemd()
{
	echo \* stopping zapret service

	"$SYSTEMCTL" daemon-reload
	"$SYSTEMCTL" disable zapret
	"$SYSTEMCTL" stop zapret
}

service_start_systemd()
{
	echo \* starting zapret service

	systemctl start zapret || {
		echo could not start zapret service
		exitp 30
	}
}

download_list()
{
	[ -x "$GET_LIST" ] &&	{
		echo \* downloading blocked ip/host list

		# can be txt or txt.gz
		rm -f "$EXEDIR/ipset/zapret-ip.txt"* "$EXEDIR/ipset/zapret-ip-user.txt"* \
			"$EXEDIR/ipset/zapret-ip-ipban.txt"* "$EXEDIR/ipset/zapret-ip-user-ipban.txt"* \
			"$EXEDIR/ipset/zapret-hosts.txt"*
		"$GET_LIST" || {
			echo could not download ip list
			exitp 25
		}
	}
}

install_systemd()
{
	INIT_SCRIPT_SRC=$EXEDIR/init.d/sysv/zapret

	check_location copy_all
	check_prerequisites_linux
	service_stop_systemd
	install_binaries
	ask_config
	service_install_systemd
	download_list
	# desktop system : likely it will be up at daytime
	crontab_add 9 21
	service_start_systemd
}





check_kmod()
{
	[ -f "/lib/modules/$(uname -r)/$1.ko" ]
}
check_package_exists_openwrt()
{
	[ -n "$(opkg list $1)" ]
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

check_prerequisites_openwrt()
{
	echo \* checking prerequisites
	
	local PKGS="iptables-mod-extra iptables-mod-nfqueue iptables-mod-filter iptables-mod-ipopt ipset curl"
	local UPD=0
	
	# in recent lede/openwrt iptable_raw in separate package
	if check_kmod iptable_raw && check_packages_openwrt $PKGS ; then
		echo everything is present
	else
		echo \* installing prerequisites
		
		opkg update
		UPD=1
		if check_package_exists_openwrt kmod-ipt-raw ; then PKGS="$PKGS kmod-ipt-raw" ; fi
		opkg install $PKGS || {
			echo could not install prerequisites
			exitp 6
		}
	fi
	
	[ -x "/usr/bin/gzip" ] || {
		echo your system uses default busybox gzip. its several times slower than gnu gzip.
		echo ip/host list scripts will run much faster with gnu gzip
		echo installer can install gnu gzip but it requires about 100 Kb space
		echo -n "do you want to install gnu gzip (Y/N) ? "
		read A
		if [ "$A" = "Y" ] || [ "$A" = "y" ]; then
			[ "$UPD" = "0" ] && {
				opkg update
				UPD=1
			}
			opkg install gzip
		fi
	}
	[ -x "/usr/bin/grep" ] || {
		echo your system uses default busybox grep. its damn infinite slow with -f option
		echo get_combined.sh will be severely impacted
		echo installer can install gnu grep but it requires about 0.5 Mb space
		echo -n "do you want to install gnu grep (Y/N) ? "
		read A
		if [ "$A" = "Y" ] || [ "$A" = "y" ]; then
			[ "$UPD" = "0" ] && {
				opkg update
				UPD=1
			}
			opkg install grep
		fi
	}
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
		i=$(($i+1))
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
	echo \* installing firewall script
	
	[ -n "MODE" ] || {
		echo should specify MODE in $ZAPRET_CONFIG
		exitp 7
	}
	
	local FW_SCRIPT_SRC="$FW_SCRIPT_SRC_DIR.$MODE"
	[ -f "$FW_SCRIPT_SRC" ] || {
		echo firewall script $FW_SCRIPT_SRC not found. removing firewall include
		openwrt_fw_section_del
		rm -f "$OPENWRT_FW_INCLUDE"
		return
	}
	echo "linking : $FW_SCRIPT_SRC => $OPENWRT_FW_INCLUDE"
	ln -fs "$FW_SCRIPT_SRC" "$OPENWRT_FW_INCLUDE"
	
	openwrt_fw_section_configure
}

restart_openwrt_firewall()
{
	echo \* restarting firewall

	fw3 -q restart || {
		echo could not restart firewall
		exitp 30
	}
}

install_sysv_init()
{
	echo \* installing init script

	[ -x "$INIT_SCRIPT" ] && "$INIT_SCRIPT" stop
	ln -fs "$INIT_SCRIPT_SRC" "$INIT_SCRIPT"
	"$INIT_SCRIPT" enable
}

service_start_sysv()
{
	echo \* starting zapret service

	"$INIT_SCRIPT" start || {
		echo could not start zapret service
		exitp 30
	}
}



install_openwrt()
{
	INIT_SCRIPT_SRC=$EXEDIR/init.d/openwrt/zapret
	FW_SCRIPT_SRC_DIR=$EXEDIR/init.d/openwrt/firewall.zapret
	OPENWRT_FW_INCLUDE=/etc/firewall.zapret
	
	check_location copy_minimal
	check_prerequisites_openwrt
	install_binaries
	ask_config
	install_sysv_init
	download_list
	# router system : works 24/7. night is the best time
	crontab_add 0 6
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