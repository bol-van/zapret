GET_LIST_PREFIX=/ipset/get_

SYSTEMD_DIR=/lib/systemd
[ -d "$SYSTEMD_DIR" ] || SYSTEMD_DIR=/usr/lib/systemd
[ -d "$SYSTEMD_DIR" ] && SYSTEMD_SYSTEM_DIR="$SYSTEMD_DIR/system"

INIT_SCRIPT=/etc/init.d/zapret


exitp()
{
	echo
	echo press enter to continue
	read A
	exit $1
}

extract_var_def()
{
	# $1 - var name
	# this sed script parses single or multi line shell var assignments with optional ' or " enclosure
	sed -n \
"/^$1=\"/ {
:s1
/\".*\"/ {
 p
 b
}
N
t c1
b s1
:c1
}
/^$1='/ {
:s2
/'.*'/ {
 p
 b
}
N
t c2
b s2
:c2
}
/^$1=/p
"
}
replace_var_def()
{
	# $1 - var name
	# $2 - new val
	# $3 - conf file
	# this sed script replaces single or multi line shell var assignments with optional ' or " enclosure
	local repl
	if [ -z "$2" ]; then
		repl="#$1="
	elif contains "$2" " "; then
		repl="$1=\"$2\""
	else
		repl="$1=$2"
	fi
	local script=\
"/^#*[[:space:]]*$1=\"/ {
:s1
/\".*\"/ {
 c\\
$repl
 b
}
N
t c1
b s1
:c1
}
/^#*[[:space:]]*$1='/ {
:s2
/'.*'/ {
 c\\
$repl
 b
}
N
t c2
b s2
:c2
}
/^#*[[:space:]]*$1=/c\\
$repl"
	# there's incompatibility with -i option on MacOS/BSD and busybox/GNU
	if [ "$UNAME" = "Linux" ]; then
		sed -i -e "$script" "$3"
	else
		sed -i '' -e "$script" "$3"
	fi
}

parse_var_checked()
{
	# $1 - file name
	# $2 - var name

	local tmp="/tmp/zvar-pid-$$.sh"
	local v
	cat "$1" | extract_var_def "$2" >"$tmp"
	. "$tmp"
	rm -f "$tmp"
	eval v="\$$2"
	# trim
	v="$(echo "$v" | trim)"
	eval $2=\""$v"\"
}
parse_vars_checked()
{
	# $1 - file name
	# $2,$3,... - var names
	local f="$1"
	shift
	while [ -n "$1" ]; do
		parse_var_checked "$f" $1
		shift
	done	
}
edit_file()
{
	# $1 - file name
	local ed="$EDITOR"
	[ -n "$ed" ] || {
		for e in mcedit nano vim vi; do
			exists "$e" && {
				ed="$e"
				break
			}
		done
	}
	[ -n "$ed" ] && "$ed" "$1"
}
echo_var()
{
	local v
	eval v="\$$1"
	if find_str_in_list $1 "$EDITVAR_NEWLINE_VARS"; then
		echo "$1=\""
		echo "$v\"" | tr '\n' ' ' | tr -d '\r' | sed -e 's/^ *//' -e 's/ *$//' -e "s/$EDITVAR_NEWLINE_DELIMETER /$EDITVAR_NEWLINE_DELIMETER\n/g"
	else
		if contains "$v" " "; then
			echo $1=\"$v\"
		else
			echo $1=$v
		fi
	fi
}
edit_vars()
{
	# $1,$2,... - var names
	local n=1 var tmp="/tmp/zvars-pid-$$.txt"
	rm -f "$tmp"
	while : ; do
		eval var="\${$n}"
		[ -n "$var" ] || break
		echo_var $var >> "$tmp"
		n=$(($n+1))
	done
	edit_file "$tmp" && parse_vars_checked "$tmp" "$@"
	rm -f "$tmp"
}

list_vars()
{
	while [ -n "$1" ] ; do
		echo_var $1
		shift
	done
	echo
}

openrc_test()
{
	exists rc-update || return 1
	# some systems do not usse openrc-init but launch openrc from inittab
	[ "$INIT" = "openrc-init" ] || grep -qE "sysinit.*openrc" /etc/inittab 2>/dev/null
}
check_system()
{
	# $1 - nonempty = do not fail on unknown rc system

	echo \* checking system

	SYSTEM=
	SUBSYS=
	SYSTEMCTL="$(whichq systemctl)"

	get_fwtype
	OPENWRT_FW3=
	OPENWRT_FW4=

	local info
	UNAME=$(uname)
	if [ "$UNAME" = "Linux" ]; then
		# do not use 'exe' because it requires root
		local INIT="$(sed 's/\x0/\n/g' /proc/1/cmdline | head -n 1)"
		[ -L "$INIT" ] && INIT=$(readlink "$INIT")
		INIT="$(basename "$INIT")"
		# some distros include systemctl without systemd
		if [ -d "$SYSTEMD_DIR" ] && [ -x "$SYSTEMCTL" ] && [ "$INIT" = "systemd" ]; then
			SYSTEM=systemd
			[ -f "$EXEDIR/init.d/sysv/functions" ] && . "$EXEDIR/init.d/sysv/functions"
		elif [ -f "/etc/openwrt_release" ] && exists opkg || exists apk && exists uci && [ "$INIT" = "procd" ] ; then
			SYSTEM=openwrt
			OPENWRT_PACKAGER=opkg
			OPENWRT_PACKAGER_INSTALL="opkg install"
			OPENWRT_PACKAGER_UPDATE="opkg update"
			exists apk && {
				OPENWRT_PACKAGER=apk
				OPENWRT_PACKAGER_INSTALL="apk add"
				OPENWRT_PACKAGER_UPDATE=
			}
			info="package manager $OPENWRT_PACKAGER\n"
			if openwrt_fw3 ; then
				OPENWRT_FW3=1
				info="${info}firewall fw3"
				if is_ipt_flow_offload_avail; then
					info="$info. hardware flow offloading requires iptables."
				else
					info="$info. flow offloading unavailable."
				fi
			elif openwrt_fw4; then
				OPENWRT_FW4=1
				info="${info}firewall fw4. flow offloading requires nftables."
			fi
			[ -f "$EXEDIR/init.d/openwrt/functions" ] && . "$EXEDIR/init.d/openwrt/functions"
		elif openrc_test; then
			SYSTEM=openrc
			[ -f "$EXEDIR/init.d/sysv/functions" ] && . "$EXEDIR/init.d/sysv/functions"
		else
			echo system is not either systemd, openrc or openwrt based
			echo easy installer can set up config settings but can\'t configure auto start
			echo you have to do it manually. check readme.md for manual setup info.
			if [ -n "$1" ] || ask_yes_no N "do you want to continue"; then
			    SYSTEM=linux
			else
			    exitp 5
			fi
			[ -f "$EXEDIR/init.d/sysv/functions" ] && . "$EXEDIR/init.d/sysv/functions"
		fi
		linux_get_subsys
	elif [ "$UNAME" = "Darwin" ]; then
		SYSTEM=macos
		[ -f "$EXEDIR/init.d/macos/functions" ] && . "$EXEDIR/init.d/macos/functions"
	else
		echo easy installer only supports Linux and MacOS. check readme.md for supported systems and manual setup info.
		exitp 5
	fi
	echo system is based on $SYSTEM
	[ -n "$info" ] && printf "${info}\n"
}

get_free_space_mb()
{
    df -m $PWD | awk '/[0-9]%/{print $(NF-2)}'
}
get_ram_kb()
{
    grep MemTotal /proc/meminfo | awk '{print $2}'
}
get_ram_mb()
{
    local R=$(get_ram_kb)
    echo $(($R/1024))
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
crontab_del_quiet()
{
	exists crontab || return

	CRONTMP=/tmp/cron.tmp
	crontab -l >$CRONTMP 2>/dev/null
	if grep -q "$GET_LIST_PREFIX" $CRONTMP; then
		grep -v "$GET_LIST_PREFIX" $CRONTMP >$CRONTMP.2
		crontab $CRONTMP.2
		rm -f $CRONTMP.2
	fi
	rm -f $CRONTMP
}
crontab_add()
{
	# $1 - hour min
	# $2 - hour max
	[ -x "$GET_LIST" ] &&	{
		echo \* adding crontab entry

		if exists crontab; then
			CRONTMP=/tmp/cron.tmp
			crontab -l >$CRONTMP 2>/dev/null
			if grep -q "$GET_LIST_PREFIX" $CRONTMP; then
				echo some entries already exist in crontab. check if this is corrent :
				grep "$GET_LIST_PREFIX" $CRONTMP
			else
				end_with_newline <"$CRONTMP" || echo >>"$CRONTMP"
				echo "$(random 0 59) $(random $1 $2) */2 * * $GET_LIST" >>$CRONTMP
				crontab $CRONTMP
			fi
			rm -f $CRONTMP
		else
			echo '!!! CRON IS ABSENT !!! LISTS AUTO UPDATE WILL NOT WORK !!!'
		fi
	}
}
cron_ensure_running()
{
	# if no crontabs present in /etc/cron openwrt init script does not launch crond. this is default
	[ "$SYSTEM" = "openwrt" ] && {
		/etc/init.d/cron enable
		/etc/init.d/cron start
	}
}


service_start_systemd()
{
	echo \* starting zapret service

	"$SYSTEMCTL" start zapret || {
		echo could not start zapret service
		exitp 30
	}
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

install_sysv_init()
{
	# $1 - "0"=disable
	echo \* installing init script

	[ -x "$INIT_SCRIPT" ] && {
		"$INIT_SCRIPT" stop
		"$INIT_SCRIPT" disable
	}
	ln -fs "$INIT_SCRIPT_SRC" "$INIT_SCRIPT"
	[ "$1" != "0" ] && "$INIT_SCRIPT" enable
}
install_openrc_init()
{
	# $1 - "0"=disable
	echo \* installing init script

	[ -x "$INIT_SCRIPT" ] && {
		"$INIT_SCRIPT" stop
		rc-update del zapret
	}
	ln -fs "$INIT_SCRIPT_SRC" "$INIT_SCRIPT"
	[ "$1" != "0" ] && rc-update add zapret
}
service_remove_openrc()
{
	echo \* removing zapret service

	[ -x "$INIT_SCRIPT" ] && {
		rc-update del zapret
		"$INIT_SCRIPT" stop
	}
	rm -f "$INIT_SCRIPT"
}
service_start_sysv()
{
	[ -x "$INIT_SCRIPT" ] && {
		echo \* starting zapret service
		"$INIT_SCRIPT" start || {
			echo could not start zapret service
			exitp 30
		}
	}
}
service_stop_sysv()
{
	[ -x "$INIT_SCRIPT" ] && {
		echo \* stopping zapret service
		"$INIT_SCRIPT" stop
	}
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

check_kmod()
{
	[ -f "/lib/modules/$(uname -r)/$1.ko" ]
}
check_package_exists_openwrt()
{
	[ -n "$($OPENWRT_PACKAGER list $1)" ]
}
check_package_openwrt()
{
	case $OPENWRT_PACKAGER in
		opkg)
			[ -n "$(opkg list-installed $1)" ] && return 0
			local what="$(opkg whatprovides $1 | tail -n +2 | head -n 1)"
			[ -n "$what" ] || return 1
			[ -n "$(opkg list-installed $what)" ]
			;;
		apk)
			apk info -e $1
			;;
	esac
}
check_packages_openwrt()
{
	for pkg in $@; do
		check_package_openwrt $pkg || return
	done
}

install_openwrt_iface_hook()
{
	echo \* installing ifup hook
	
	ln -fs "$OPENWRT_IFACE_HOOK" /etc/hotplug.d/iface
}
remove_openwrt_iface_hook()
{
	echo \* removing ifup hook
	
	rm -f /etc/hotplug.d/iface/??-zapret
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

	local id="$(openwrt_fw_section_find $1)"
	[ -n "$id" ] && {
		uci delete firewall.@include[$id] && uci commit firewall
		rm -f "$OPENWRT_FW_INCLUDE$1"
	}
}
openwrt_fw_section_add()
{
	openwrt_fw_section_find ||
	{
		uci add firewall include >/dev/null || return
		echo -1
	}
}
openwrt_fw_section_configure()
{
	local id="$(openwrt_fw_section_add $1)"
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
	echo \* installing firewall script $1
	
	[ -n "MODE" ] || {
		echo should specify MODE in $ZAPRET_CONFIG
		exitp 7
	}
	
	echo "linking : $FW_SCRIPT_SRC => $OPENWRT_FW_INCLUDE"
	ln -fs "$FW_SCRIPT_SRC" "$OPENWRT_FW_INCLUDE"
	
	openwrt_fw_section_configure $1
}
restart_openwrt_firewall()
{
	echo \* restarting firewall

	local FW=fw4
	[ -n "$OPENWRT_FW3" ] && FW=fw3
	exists $FW && $FW -q restart || {
		echo could not restart firewall $FW
	}
}
remove_openwrt_firewall()
{
	echo \* removing firewall script
	
	openwrt_fw_section_del
	# from old zapret versions. now we use single include
	openwrt_fw_section_del 6
}

clear_ipset()
{
	echo "* clearing ipset(s)"

	# free some RAM
	"$IPSET_DIR/create_ipset.sh" clear
}


service_install_macos()
{
	echo \* installing zapret service

	ln -fs "$ZAPRET_BASE/init.d/macos/zapret.plist" /Library/LaunchDaemons
}
service_start_macos()
{
	echo \* starting zapret service

	"$INIT_SCRIPT_SRC" start
}
service_stop_macos()
{
	echo \* stopping zapret service

	"$INIT_SCRIPT_SRC" stop
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

sedi()
{
	# MacOS doesnt support -i without parameter. busybox doesnt support -i with parameter.
	# its not possible to put "sed -i ''" to a variable and then use it
	if [ "$SYSTEM" = "macos" ]; then
		sed -i '' "$@"
	else
		sed -i "$@"
	fi
}

write_config_var()
{
	# $1 - mode var
	local M
	eval M="\$$1"
	# replace / => \/
	#M=${M//\//\\\/}
	M=$(echo $M | sed 's/\//\\\//g' | trim)
	grep -q "^[[:space:]]*$1=\|^#*[[:space:]]*$1=" "$ZAPRET_CONFIG" || {
		# var does not exist in config. add it
		echo $1= >>"$ZAPRET_CONFIG"
	}
	replace_var_def $1 "$M" "$ZAPRET_CONFIG"
}

no_prereq_exit()
{
	echo could not install prerequisites
	exitp 6
}
check_prerequisites_linux()
{
	echo \* checking prerequisites

	local s cmd PKGS UTILS req="curl curl"
	local APTGET DNF YUM PACMAN ZYPPER EOPKG APK
	case "$FWTYPE" in
		iptables)
			req="$req iptables iptables ip6tables iptables ipset ipset"
			;;
		nftables)
			req="$req nft nftables"
			;;
	esac

	PKGS=$(for s in $req; do echo $s; done |
		while read cmd; do
			read pkg
			exists $cmd || echo $pkg
		done | sort -u | xargs)
	UTILS=$(for s in $req; do echo $s; done |
		while read cmd; do
			read pkg
			echo $cmd
		done | sort -u | xargs)

	if [ -z "$PKGS" ] ; then
		echo required utilities exist : $UTILS
	else
		echo \* installing prerequisites

		echo packages required : $PKGS

		APTGET=$(whichq apt-get)
		DNF=$(whichq dnf)
		YUM=$(whichq yum)
		PACMAN=$(whichq pacman)
		ZYPPER=$(whichq zypper)
		EOPKG=$(whichq eopkg)
		APK=$(whichq apk)
		if [ -x "$APTGET" ] ; then
			"$APTGET" update
			"$APTGET" install -y --no-install-recommends $PKGS dnsutils || no_prereq_exit
		elif [ -x "$DNF" ] ; then
			"$DNF" -y install $PKGS || no_prereq_exit
		elif [ -x "$YUM" ] ; then
			"$YUM" -y install $PKGS || no_prereq_exit
		elif [ -x "$PACMAN" ] ; then
			"$PACMAN" -Syy
			"$PACMAN" --noconfirm -S $PKGS || no_prereq_exit
		elif [ -x "$ZYPPER" ] ; then
			"$ZYPPER" --non-interactive install $PKGS || no_prereq_exit
		elif [ -x "$EOPKG" ] ; then
			"$EOPKG" -y install $PKGS || no_prereq_exit
		elif [ -x "$APK" ] ; then
			"$APK" update
			# for alpine
			[ "$FWTYPE" = iptables ] && [ -n "$($APK list ip6tables)" ] && PKGS="$PKGS ip6tables"
			"$APK" add $PKGS || no_prereq_exit
		else
			echo supported package manager not found
			echo you must manually install : $UTILS
			exitp 5
		fi
	fi
}

removable_pkgs_openwrt()
{
	local pkg PKGS2
	[ -n "$OPENWRT_FW4" ] && PKGS2="$PKGS2 iptables-zz-legacy iptables ip6tables-zz-legacy ip6tables"
	[ -n "$OPENWRT_FW3" ] && PKGS2="$PKGS2 nftables-json nftables-nojson nftables"
	PKGS=
	for pkg in $PKGS2; do
		check_package_exists_openwrt $pkg && PKGS="${PKGS:+$PKGS }$pkg"
	done
	PKGS="ipset iptables-mod-extra iptables-mod-nfqueue iptables-mod-filter iptables-mod-ipopt iptables-mod-conntrack-extra ip6tables-mod-nat ip6tables-extra kmod-nft-queue gzip coreutils-sort coreutils-sleep curl $PKGS"
}

openwrt_fix_broken_apk_uninstall_scripts()
{
	# at least in early snapshots with apk removing gnu gzip, sort, ... does not restore links to busybox
	# system may become unusable
	exists sort || { echo fixing missing sort; ln -fs /bin/busybox /usr/bin/sort; }
	exists gzip || { echo fixing missing gzip; ln -fs /bin/busybox /bin/gzip; }
	exists sleep || { echo fixing missing sleep; ln -fs /bin/busybox /bin/sleep; }
}

remove_extra_pkgs_openwrt()
{
	local PKGS
	echo \* remove dependencies
	removable_pkgs_openwrt
	echo these packages may have been installed by install_easy.sh : $PKGS
	ask_yes_no N "do you want to remove them" && {
		case $OPENWRT_PACKAGER in
			opkg)
				opkg remove --autoremove $PKGS
				;;
			apk)
				apk del $PKGS
				openwrt_fix_broken_apk_uninstall_scripts
				;;
		esac
	}
}

check_prerequisites_openwrt()
{
	echo \* checking prerequisites

	local PKGS="curl" UPD=0 local pkg_iptables

	case "$FWTYPE" in
		iptables)
			pkg_iptables=iptables
			check_package_exists_openwrt iptables-zz-legacy && pkg_iptables=iptables-zz-legacy
			PKGS="$PKGS ipset $pkg_iptables iptables-mod-extra iptables-mod-nfqueue iptables-mod-filter iptables-mod-ipopt iptables-mod-conntrack-extra"
			check_package_exists_openwrt ip6tables-zz-legacy && pkg_iptables=ip6tables-zz-legacy
			[ "$DISABLE_IPV6" = 1 ] || PKGS="$PKGS $pkg_iptables ip6tables-mod-nat ip6tables-extra"
			;;
		nftables)
			PKGS="$PKGS nftables kmod-nft-nat kmod-nft-offload kmod-nft-queue"
			;;
	esac

	if check_packages_openwrt $PKGS ; then
		echo everything is present
	else
		echo \* installing prerequisites

		$OPENWRT_PACKAGER_UPDATE
		UPD=1
		$OPENWRT_PACKAGER_INSTALL $PKGS || {
			echo could not install prerequisites
			exitp 6
		}
	fi
	
	is_linked_to_busybox gzip && {
		echo
		echo your system uses default busybox gzip. its several times slower than GNU gzip.
		echo ip/host list scripts will run much faster with GNU gzip
		echo installer can install GNU gzip but it requires about 100 Kb space
		if ask_yes_no N "do you want to install GNU gzip"; then
			[ "$UPD" = "0" ] && {
				$OPENWRT_PACKAGER_UPDATE
				UPD=1
			}
			$OPENWRT_PACKAGER_INSTALL --force-overwrite gzip
		fi
	}
	is_linked_to_busybox sort && {
		echo
		echo your system uses default busybox sort. its much slower and consumes much more RAM than GNU sort
		echo ip/host list scripts will run much faster with GNU sort
		echo installer can install GNU sort but it requires about 100 Kb space
		if ask_yes_no N "do you want to install GNU sort"; then
			[ "$UPD" = "0" ] && {
				$OPENWRT_PACKAGER_UPDATE
				UPD=1
			}
			$OPENWRT_PACKAGER_INSTALL --force-overwrite coreutils-sort
		fi
	}
	[ "$FSLEEP" = 0 ] && is_linked_to_busybox sleep && {
		echo
		echo no methods of sub-second sleep were found.
		echo if you want to speed up blockcheck install coreutils-sleep. it requires about 40 Kb space
		if ask_yes_no N "do you want to install COREUTILS sleep"; then
			[ "$UPD" = "0" ] && {
				$OPENWRT_PACKAGER_UPDATE
				UPD=1
			}
			$OPENWRT_PACKAGER_INSTALL --force-overwrite coreutils-sleep
			fsleep_setup
		fi
	}
}



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

dry_run_tpws_()
{
	local TPWS="$ZAPRET_BASE/tpws/tpws"
	echo verifying tpws options
	"$TPWS" --dry-run ${WS_USER:+--user=$WS_USER} "$@"
}
dry_run_nfqws_()
{
	local NFQWS="$ZAPRET_BASE/nfq/nfqws"
	echo verifying nfqws options
	"$NFQWS" --dry-run ${WS_USER:+--user=$WS_USER} "$@"
}
dry_run_tpws()
{
	[ "$TPWS_ENABLE" = 1 ] || return 0
	local opt="$TPWS_OPT" port=${TPPORT_SOCKS:-988}
	filter_apply_hostlist_target opt
	dry_run_tpws_ --port=$port $opt
}
dry_run_tpws_socks()
{
	[ "$TPWS_SOCKS_ENABLE" = 1 ] || return 0
	local opt="$TPWS_SOCKS_OPT" port=${TPPORT:-987}
	filter_apply_hostlist_target opt
	dry_run_tpws_ --port=$port --socks $opt
}
dry_run_nfqws()
{
	[ "$NFQWS_ENABLE" = 1 ] || return 0
	local opt="$NFQWS_OPT" qn=${QNUM:-200}
	filter_apply_hostlist_target opt
	dry_run_nfqws_ --qnum=$qn $opt
}
