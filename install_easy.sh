#!/bin/sh

# automated script for easy installing zapret

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
IPSET_DIR="$EXEDIR/ipset"
ZAPRET_CONFIG="$EXEDIR/config"
ZAPRET_BASE="$EXEDIR"

[ -f "$ZAPRET_CONFIG" ] || cp "${ZAPRET_CONFIG}.default" "$ZAPRET_CONFIG"
. "$ZAPRET_CONFIG"
. "$ZAPRET_BASE/common/base.sh"
. "$ZAPRET_BASE/common/elevate.sh"
. "$ZAPRET_BASE/common/fwtype.sh"
. "$ZAPRET_BASE/common/dialog.sh"
. "$ZAPRET_BASE/common/ipt.sh"
. "$ZAPRET_BASE/common/installer.sh"
. "$ZAPRET_BASE/common/virt.sh"

# install target
ZAPRET_TARGET=/opt/zapret

GET_LIST="$IPSET_DIR/get_config.sh"

[ -n "$TPPORT" ] || TPPORT=988

check_readonly_system()
{
	local RO
	echo \* checking readonly system
        case $SYSTEM in
		systemd)
			[ -w "$SYSTEMD_SYSTEM_DIR" ] || RO=1
			;;
		openrc)
			[ -w "$(dirname "$INIT_SCRIPT")" ] || RO=1
			;;
	esac
	[ -z "$RO" ] || {
		echo '!!! READONLY SYSTEM DETECTED !!!'
		echo '!!! WILL NOT BE ABLE TO CONFIGURE STARTUP !!!'
		echo '!!! MANUAL STARTUP CONFIGURATION IS REQUIRED !!!'
		ask_yes_no N "do you want to continue" || exitp 5
	}
}

check_bins()
{
	echo \* checking executables

	fix_perms_bin_test "$EXEDIR"
	local arch="$(get_bin_arch)"
	local make_target
	[ "$FORCE_BUILD" = "1" ] && {
		echo forced build mode
		if [ "$arch" = "my" ]; then
			echo already compiled
		else
			arch=""
		fi
	}
	if [ -n "$arch" ] ; then
		echo found architecture "\"$arch\""
	elif [ -f "$EXEDIR/Makefile" ] && exists make; then
		echo trying to compile
		[ "$SYSTEM" = "macos" ] && make_target=mac
		make -C "$EXEDIR" $make_target || {
			echo could not compile
			make -C "$EXEDIR" clean
			exitp 8
		}
		echo compiled
	else
		echo build tools not found
		exitp 8
	fi
}

call_install_bin()
{
	sh "$EXEDIR/install_bin.sh" $1
}
get_bin_arch()
{
	call_install_bin getarch
}

install_binaries()
{
	echo \* installing binaries

	call_install_bin || {
		echo compatible binaries not found
		exitp 8
	}
}

select_mode_mode()
{
	local edited v vars MODES="tpws tpws-socks nfqws filter custom"
	[ "$SYSTEM" = "macos" ] && MODES="tpws tpws-socks filter custom"
	echo
	echo select MODE :
	ask_list MODE "$MODES" tpws && write_config_var MODE

	case $MODE in
		tpws)
			vars="TPWS_OPT"
			;;
		nfqws)
			vars="NFQWS_OPT_DESYNC NFQWS_OPT_DESYNC_HTTP NFQWS_OPT_DESYNC_HTTPS NFQWS_OPT_DESYNC_HTTP6 NFQWS_OPT_DESYNC_HTTPS6 NFQWS_OPT_DESYNC_QUIC NFQWS_OPT_DESYNC_QUIC6"
			;;
	esac
	[ -n "$vars" ] && {
		echo
		while [ 1=1 ]; do
			for var in $vars; do
				eval v="\$$var"
				echo $var=\"$v\"
			done
			ask_yes_no N "do you want to edit the options" || {
				[ -n "$edited" ] && {
					for var in $vars; do
						write_config_var $var
					done
				}
				break
			}
			edit_vars $vars
			edited=1
			echo ..edited..
		done
	}
}
select_mode_http()
{
	[ "$MODE" != "filter" ] && [ "$MODE" != "tpws-socks" ] && {
		echo
		ask_yes_no_var MODE_HTTP "enable http support"
		write_config_var MODE_HTTP
	}
}
select_mode_keepalive()
{
	[ "$MODE" = "nfqws" ] && [ "$MODE_HTTP" = "1" ] && {
		echo
		echo enable keep alive support only if DPI checks every outgoing packet for http signature
		echo dont enable otherwise because it consumes more cpu resources
		ask_yes_no_var MODE_HTTP_KEEPALIVE "enable http keep alive support"
		write_config_var MODE_HTTP_KEEPALIVE
	}
}
select_mode_https()
{
	[ "$MODE" != "filter" ] && [ "$MODE" != "tpws-socks" ] && {
		echo
		ask_yes_no_var MODE_HTTPS "enable https support"
		write_config_var MODE_HTTPS
	}
}
select_mode_quic()
{
	[ "$SUBSYS" = "keenetic" ] && {
		echo
		echo "WARNING ! Keenetic is not officially supported by zapret."
		echo "WARNING ! This firmware requires additional manual iptables setup to support udp desync properly."
		echo "WARNING ! Keenetic uses proprietary ndmmark to limit MASQUERADE."
		echo "WARNING ! Desynced packets may go outside without MASQUERADE with LAN source ip."
		echo "WARNING ! To fix this you need to add additional MASQUERADE rule to iptables nat table."
		echo "WARNING ! Installer WILL NOT fix it for you automatically."
		echo "WARNING ! If you cannot understand what it is all about - do not enable QUIC."
	}
	[ "$MODE" != "filter" ] && [ "$MODE" != "tpws-socks" ] && [ "$MODE" != "tpws" ] && {
		echo
		ask_yes_no_var MODE_QUIC "enable quic support"
		write_config_var MODE_QUIC
	}
}
select_mode_filter()
{
	local filter="none ipset hostlist autohostlist"
	[ "$MODE" = "tpws-socks" ] && filter="none hostlist autohostlist"
	echo
	echo select filtering :
	ask_list MODE_FILTER "$filter" none && write_config_var MODE_FILTER
}
select_mode()
{
	select_mode_mode
	select_mode_iface
	select_mode_http
	select_mode_keepalive
	select_mode_https
	select_mode_quic
	select_mode_filter
}

select_getlist()
{
	if [ "$MODE_FILTER" = "ipset" -o "$MODE_FILTER" = "hostlist" ]; then
		local D=N
		[ -n "$GETLIST" ] && D=Y
		echo
		if ask_yes_no $D "do you want to auto download ip/host list"; then
			if [ "$MODE_FILTER" = "hostlist" ] ; then
				GETLISTS="get_antizapret_domains.sh get_reestr_resolvable_domains.sh get_reestr_hostlist.sh"
				GETLIST_DEF="get_antizapret_domains.sh"
			else
				GETLISTS="get_user.sh get_antifilter_ip.sh get_antifilter_ipsmart.sh get_antifilter_ipsum.sh get_antifilter_ipresolve.sh get_antifilter_allyouneed.sh get_reestr_resolve.sh get_reestr_preresolved.sh get_reestr_preresolved_smart.sh"
				GETLIST_DEF="get_antifilter_allyouneed.sh"
			fi
			ask_list GETLIST "$GETLISTS" "$GETLIST_DEF" && write_config_var GETLIST
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

ask_config_offload()
{
	[ "$FWTYPE" = nftables ] || is_ipt_flow_offload_avail && {
		echo
		echo flow offloading can greatly increase speed on slow devices and high speed links \(usually 150+ mbits\)
		if [ "$SYSTEM" = openwrt ]; then
			echo unfortuantely its not compatible with most nfqws options. nfqws traffic must be exempted from flow offloading.
			echo donttouch = disable system flow offloading setting if nfqws mode was selected, dont touch it otherwise and dont configure selective flow offloading
			echo none = always disable system flow offloading setting and dont configure selective flow offloading
			echo software = always disable system flow offloading setting and configure selective software flow offloading
			echo hardware = always disable system flow offloading setting and configure selective hardware flow offloading
		else
			echo offloading is applicable only to forwarded traffic. it has no effect on outgoing traffic
			echo hardware flow offloading is available only on specific supporting hardware. most likely will not work on a generic system
		fi
		echo offloading breaks traffic shaper
		echo select flow offloading :
		local options="none software hardware"
		local default="none"
		[ "$SYSTEM" = openwrt ] && {
			options="donttouch none software hardware"
			default="donttouch"
		}
		ask_list FLOWOFFLOAD "$options" $default && write_config_var FLOWOFFLOAD
	}
}

ask_config_tmpdir()
{
	# ask tmpdir change for low ram systems with enough free disk space
	[ -n "$GETLIST" ] && [ $(get_free_space_mb "$EXEDIR/tmp") -ge 128 ] && [ $(get_ram_mb) -le 400 ] && {
		echo
		echo /tmp in openwrt is tmpfs. on low RAM systems there may be not enough RAM to store downloaded files
		echo default tmpfs has size of 50% RAM
		echo "RAM  : $(get_ram_mb) Mb"
		echo "DISK : $(get_free_space_mb) Mb"
		echo select temp file location 
		[ -z "$TMPDIR" ] && TMPDIR=/tmp
		ask_list TMPDIR "/tmp $EXEDIR/tmp" && {
		    [ "$TMPDIR" = "/tmp" ] && TMPDIR=
		    write_config_var TMPDIR
		}
	}
}

nft_flow_offload()
{
	[ "$UNAME" = Linux -a "$FWTYPE" = nftables -a "$MODE" != "tpws-socks" ] && [ "$FLOWOFFLOAD" = software -o "$FLOWOFFLOAD" = hardware ]
}

ask_iface()
{
	# $1 - var to ask
	# $2 - additional name for empty string synonim

	local ifs i0 def new
	eval def="\$$1"

	[ -n "$2" ] && i0="$2 "
	case $SYSTEM in
		macos)
			ifs="$(ifconfig -l)"
			;;
		*)
			ifs="$(ls /sys/class/net)"
			;;
	esac
	[ -z "$def" ] && eval $1="$2"
	ask_list $1 "$i0$ifs" && {
		eval new="\$$1"
		[ "$new" = "$2" ] && eval $1=""
		write_config_var $1
	}
}
ask_iface_lan()
{
	echo LAN interface :
	local opt
	nft_flow_offload || opt=NONE
	ask_iface IFACE_LAN $opt
}
ask_iface_wan()
{
	echo WAN interface :
	local opt
	nft_flow_offload || opt=ANY
	ask_iface IFACE_WAN $opt
}

select_mode_iface()
{
	# openwrt has its own interface management scheme
	# filter just creates ip tables, no daemons involved
	# nfqws sits in POSTROUTING chain and unable to filter by incoming interface
	# tpws redirection works in PREROUTING chain
	# in tpws-socks mode IFACE_LAN specifies additional bind interface for the socks listener
	# it's not possible to instruct tpws to route outgoing connection to an interface (OS routing table decides)
	# custom mode can also benefit from interface names (depends on custom script code)

	if [ "$SYSTEM" = "openwrt" ] || [ "$MODE" = "filter" ]; then return; fi

	case "$MODE" in
		tpws-socks)
			echo "select LAN interface to allow socks access from your LAN. select NONE for localhost only."
			echo "expect socks on tcp port $TPPORT"
			ask_iface_lan
			;;
		tpws)
			echo "select LAN interface to operate in router mode. select NONE for local outgoing traffic only."
			if [ "$SYSTEM" = "macos" ]; then
				echo "WARNING ! OS feature \"internet sharing\" is not supported."
				echo "Only manually configured PF router is supported."
			else
				echo "WARNING ! This installer will not configure routing, NAT, ... for you. Its your responsibility."
			fi
			ask_iface_lan
			;;
		custom)
			echo "select LAN interface for your custom script (how it works depends on your code)"
			ask_iface_lan
			;;
		*)
			nft_flow_offload && {
				echo "select LAN interface for nftables flow offloading"
				ask_iface_lan
			}
			;;
	esac

	case "$MODE" in
		tpws)
			echo "select WAN interface for $MODE operations. select ANY to operate on any interface."
			[ -n "$IFACE_LAN" ] && echo "WAN filtering works only for local outgoing traffic !"
			ask_iface_wan
			;;
		nfqws)
			echo "select WAN interface for $MODE operations. select ANY to operate on any interface."
			ask_iface_wan
			;;
		custom)
			echo "select WAN interface for your custom script (how it works depends on your code)"
			ask_iface_wan
			;;
		*)
			nft_flow_offload && {
				echo "select WAN interface for nftables flow offloading"
				ask_iface_wan
			}
			;;
	esac
}

default_files()
{
	[ -f "$1/ipset/$file/zapret-hosts-user-exclude.txt" ] || cp "$1/ipset/$file/zapret-hosts-user-exclude.txt.default" "$1/ipset/$file/zapret-hosts-user-exclude.txt"
	[ -f "$1/ipset/$file/zapret-hosts-user.txt" ] || echo nonexistent.domain >> "$1/ipset/$file/zapret-hosts-user.txt"
	[ -f "$1/ipset/$file/zapret-hosts-user-ipban.txt" ] || touch "$1/ipset/$file/zapret-hosts-user-ipban.txt"
	for dir in openwrt sysv macos; do
		[ -d "$1/init.d/$dir" ] && {
			[ -f "$1/init.d/$dir/custom" ] || cp "$1/init.d/$dir/custom.default" "$1/init.d/$dir/custom"
		}
	done
}
copy_all()
{
	local dir

	cp -R "$1" "$2"
	[ -d "$2/tmp" ] || mkdir "$2/tmp"
}
copy_openwrt()
{
	local ARCH="$(get_bin_arch)"
	local BINDIR="$1/binaries/$ARCH"
	local file
	
	[ -d "$2" ] || mkdir -p "$2"

	mkdir "$2/tpws" "$2/nfq" "$2/ip2net" "$2/mdig" "$2/binaries" "$2/binaries/$ARCH" "$2/init.d" "$2/tmp" "$2/files"
	cp -R "$1/files/fake" "$2/files"
	cp -R "$1/common" "$1/ipset" "$2"
	cp -R "$1/init.d/openwrt" "$2/init.d"
	cp "$1/config" "$1/config.default" "$1/install_easy.sh" "$1/uninstall_easy.sh" "$1/install_bin.sh" "$1/install_prereq.sh" "$1/blockcheck.sh" "$2"
	cp "$BINDIR/tpws" "$BINDIR/nfqws" "$BINDIR/ip2net" "$BINDIR/mdig" "$2/binaries/$ARCH"
}

fix_perms_bin_test()
{
	[ -d "$1" ] || return
	find "$1/binaries" -name ip2net ! -perm -111 -exec chmod +x {} \;
}
fix_perms()
{
	[ -d "$1" ] || return
	find "$1" -type d -exec chmod 755 {} \;
	find "$1" -type f -exec chmod 644 {} \;
	chown -R root:root "$1"
	find "$1/binaries" '(' -name tpws -o -name dvtws -o -name nfqws -o -name ip2net -o -name mdig ')' -exec chmod 755 {} \;
	for f in \
install_bin.sh \
blockcheck.sh \
install_easy.sh \
install_prereq.sh \
files/huawei/E8372/zapret-ip \
files/huawei/E8372/unzapret-ip \
files/huawei/E8372/run-zapret-hostlist \
files/huawei/E8372/unzapret \
files/huawei/E8372/zapret \
files/huawei/E8372/run-zapret-ip \
ipset/get_exclude.sh \
ipset/clear_lists.sh \
ipset/get_antifilter_ipresolve.sh \
ipset/get_reestr_resolvable_domains.sh \
ipset/get_config.sh \
ipset/get_reestr_preresolved.sh \
ipset/get_user.sh \
ipset/get_antifilter_allyouneed.sh \
ipset/get_reestr_resolve.sh \
ipset/create_ipset.sh \
ipset/get_reestr_hostlist.sh \
ipset/get_ipban.sh \
ipset/get_antifilter_ipsum.sh \
ipset/get_antifilter_ipsmart.sh \
ipset/get_antizapret_domains.sh \
ipset/get_reestr_preresolved_smart.sh \
ipset/get_antifilter_ip.sh \
init.d/pfsense/zapret.sh \
init.d/macos/zapret \
init.d/runit/zapret/run \
init.d/runit/zapret/finish \
init.d/openrc/zapret \
init.d/sysv/zapret \
init.d/openwrt/zapret \
uninstall_easy.sh \
	; do chmod 755 "$1/$f" 2>/dev/null ; done
}


_backup_settings()
{
	local i=0
	for f in "$@"; do
		[ -f "$ZAPRET_TARGET/$f" ] && cp -f "$ZAPRET_TARGET/$f" "/tmp/zapret-bkp-$i"
		i=$(($i+1))
	done
}
_restore_settings()
{
	local i=0
	for f in "$@"; do
		[ -f "/tmp/zapret-bkp-$i" ] && mv -f "/tmp/zapret-bkp-$i" "$ZAPRET_TARGET/$f" || rm -f "/tmp/zapret-bkp-$i"
		i=$(($i+1))
	done
}
backup_restore_settings()
{
	# $1 - 1 - backup, 0 - restore
	local mode=$1
	on_off_function _backup_settings _restore_settings $mode "config" "init.d/sysv/custom" "init.d/openwrt/custom" "init.d/macos/custom" "ipset/zapret-hosts-user.txt" "ipset/zapret-hosts-user-exclude.txt" "ipset/zapret-hosts-user-ipban.txt" "ipset/zapret-hosts-auto.txt"
}

check_location()
{
	# $1 - copy function

	echo \* checking location

	# use inodes in case something is linked
	if [ -d "$ZAPRET_TARGET" ] && [ $(get_dir_inode "$EXEDIR") = $(get_dir_inode "$ZAPRET_TARGET") ]; then
		default_files "$ZAPRET_TARGET"
	else
		echo
		echo easy install is supported only from default location : $ZAPRET_TARGET
		echo currently its run from $EXEDIR
		if ask_yes_no N "do you want the installer to copy it for you"; then
			local keep=N
			if [ -d "$ZAPRET_TARGET" ]; then
				echo
				echo installer found existing $ZAPRET_TARGET
				echo directory needs to be replaced. config and custom scripts can be kept or replaced with clean version
				if ask_yes_no N "do you want to delete all files there and copy this version"; then
					echo
					ask_yes_no Y "keep config, custom scripts and user lists" && keep=Y
					[ "$keep" = "Y" ] && backup_restore_settings 1
					rm -r "$ZAPRET_TARGET"
				else
					echo refused to overwrite $ZAPRET_TARGET. exiting
					exitp 3
				fi
			fi
			local B="$(dirname "$ZAPRET_TARGET")"
			[ -d "$B" ] || mkdir -p "$B"
			$1 "$EXEDIR" "$ZAPRET_TARGET"
			fix_perms "$ZAPRET_TARGET"
			[ "$keep" = "Y" ] && backup_restore_settings 0
			echo relaunching itself from $ZAPRET_TARGET
			exec $ZAPRET_TARGET/$(basename $0)
		else
			echo copying aborted. exiting
			exitp 3
		fi
	fi
	echo running from $EXEDIR
}


service_install_systemd()
{
	echo \* installing zapret service

	if [ -w "$SYSTEMD_SYSTEM_DIR" ] ; then
		rm -f "$INIT_SCRIPT"
		ln -fs "$EXEDIR/init.d/systemd/zapret.service" "$SYSTEMD_SYSTEM_DIR"
		"$SYSTEMCTL" daemon-reload
		"$SYSTEMCTL" enable zapret || {
			echo could not enable systemd service
			exitp 20
		}
	else
		echo '!!! READONLY SYSTEM DETECTED !!! CANNOT INSTALL SYSTEMD UNITS !!!'
	fi
}

timer_install_systemd()
{
	echo \* installing zapret-list-update timer

	if [ -w "$SYSTEMD_SYSTEM_DIR" ] ; then
		"$SYSTEMCTL" disable zapret-list-update.timer
		"$SYSTEMCTL" stop zapret-list-update.timer
		ln -fs "$EXEDIR/init.d/systemd/zapret-list-update.service" "$SYSTEMD_SYSTEM_DIR"
		ln -fs "$EXEDIR/init.d/systemd/zapret-list-update.timer" "$SYSTEMD_SYSTEM_DIR"
		"$SYSTEMCTL" daemon-reload
		"$SYSTEMCTL" enable zapret-list-update.timer || {
			echo could not enable zapret-list-update.timer
			exitp 20
		}
		"$SYSTEMCTL" start zapret-list-update.timer || {
			echo could not start zapret-list-update.timer
			exitp 30
		}
	else
		echo '!!! READONLY SYSTEM DETECTED !!! CANNOT INSTALL SYSTEMD UNITS !!!'
	fi
}

download_list()
{
	[ -x "$GET_LIST" ] &&	{
		echo \* downloading blocked ip/host list

		# can be txt or txt.gz
		"$IPSET_DIR/clear_lists.sh"
		"$GET_LIST"
	}
}


dnstest()
{
	# $1 - dns server. empty for system resolver
	nslookup w3.org $1 >/dev/null 2>/dev/null
}
check_dns()
{
	echo \* checking DNS

	dnstest || {
		echo -- DNS is not working. It's either misconfigured or blocked or you don't have inet access.
		return 1
	}
	echo system DNS is working
	return 0
}


install_systemd()
{
	INIT_SCRIPT_SRC="$EXEDIR/init.d/sysv/zapret"

	check_bins
	require_root
	check_readonly_system
	check_location copy_all
	check_dns
	check_virt
	service_stop_systemd
	select_fwtype
	check_prerequisites_linux
	install_binaries
	select_ipv6
	ask_config_offload
	ask_config
	service_install_systemd
	download_list
	# in case its left from old version of zapret
	crontab_del_quiet
	# now we use systemd timers
	timer_install_systemd
	service_start_systemd
}

_install_sysv()
{
	# $1 - install init script

	check_bins
	require_root
	check_readonly_system
	check_location copy_all
	check_dns
	check_virt
	service_stop_sysv
	select_fwtype
	check_prerequisites_linux
	install_binaries
	select_ipv6
	ask_config_offload
	ask_config
	$1
	download_list
	crontab_del_quiet
	# desktop system. more likely up at daytime
	crontab_add 10 22
	service_start_sysv
}

install_sysv()
{
	INIT_SCRIPT_SRC="$EXEDIR/init.d/sysv/zapret"
	_install_sysv install_sysv_init
}

install_openrc()
{
	INIT_SCRIPT_SRC="$EXEDIR/init.d/openrc/zapret"
	_install_sysv install_openrc_init
}


install_linux()
{
	INIT_SCRIPT_SRC="$EXEDIR/init.d/sysv/zapret"

	check_bins
	require_root
	check_location copy_all
	check_dns
	check_virt
	select_fwtype
	check_prerequisites_linux
	install_binaries
	select_ipv6
	ask_config_offload
	ask_config
	download_list
	crontab_del_quiet
	# desktop system. more likely up at daytime
	crontab_add 10 22
	
	echo
	echo '!!! WARNING. YOUR SETUP IS INCOMPLETE !!!'
	echo you must manually add to auto start : $INIT_SCRIPT_SRC start
	echo make sure it\'s executed after your custom/firewall iptables configuration
	echo "if your system uses sysv init : ln -fs $INIT_SCRIPT_SRC /etc/init.d/zapret ; chkconfig zapret on"
}


deoffload_openwrt_firewall()
{
	echo \* checking flow offloading

	[ "$FWTYPE" = "nftables" ] || is_ipt_flow_offload_avail || {
		echo unavailable
		return
	}

	local fo=$(uci -q get firewall.@defaults[0].flow_offloading)

	if [ "$fo" = "1" ] ; then
		local mod=0
		printf "system wide flow offloading detected. "
		case $FLOWOFFLOAD in
			donttouch)
				if [ "$MODE" = "nfqws" ]; then
					echo its incompatible with nfqws tcp data tampering. disabling
					uci set firewall.@defaults[0].flow_offloading=0
					mod=1
				else
					if [ "$MODE" = "custom" ] ; then
						echo custom mode selected !!! only you can decide whether flow offloading is compatible
					else
						echo its compatible with selected options. not disabling
					fi
				fi
			;;
		*)
			echo zapret will disable system wide offloading setting and add selective rules if required
			uci set firewall.@defaults[0].flow_offloading=0
			mod=1
		esac
		[ "$mod" = "1" ] && uci commit firewall
	else
		echo system wide software flow offloading disabled. ok
	fi
			
}



install_openwrt()
{
	INIT_SCRIPT_SRC="$EXEDIR/init.d/openwrt/zapret"
	FW_SCRIPT_SRC="$EXEDIR/init.d/openwrt/firewall.zapret"
	OPENWRT_FW_INCLUDE=/etc/firewall.zapret
	OPENWRT_IFACE_HOOK="$EXEDIR/init.d/openwrt/90-zapret"

	check_bins
	require_root
	check_location copy_openwrt
	install_binaries
	check_dns
	check_virt

	local FWTYPE_OLD=$FWTYPE

	echo \* stopping current firewall rules/daemons
	"$INIT_SCRIPT_SRC" stop_fw
	"$INIT_SCRIPT_SRC" stop_daemons

	select_fwtype
	select_ipv6
	check_prerequisites_openwrt
	ask_config
	ask_config_tmpdir
	ask_config_offload
	# stop and reinstall sysv init
	install_sysv_init
	[ "$FWTYPE_OLD" != "$FWTYPE" -a "$FWTYPE_OLD" = iptables -a -n "$OPENWRT_FW3" ] && remove_openwrt_firewall
	# free some RAM
	clear_ipset
	download_list
	crontab_del_quiet
	# router system : works 24/7. night is the best time
	crontab_add 0 6
	cron_ensure_running
	install_openwrt_iface_hook
	# in case of nftables or iptables without fw3 sysv init script also controls firewall
	[ -n "$OPENWRT_FW3" -a "$FWTYPE" = iptables ] && install_openwrt_firewall
	service_start_sysv
	deoffload_openwrt_firewall
	restart_openwrt_firewall
}



remove_pf_zapret_hooks()
{
	echo \* removing zapret PF hooks

	pf_anchors_clear
}

macos_fw_reload_trigger_clear()
{
	case "$MODE" in
		tpws|tpws-socks|custom)
			LISTS_RELOAD=
			write_config_var LISTS_RELOAD
			;;
	esac
}
macos_fw_reload_trigger_set()
{
	case "$MODE" in
		tpws|custom)
			LISTS_RELOAD="$INIT_SCRIPT_SRC reload-fw-tables"
			write_config_var LISTS_RELOAD
			;;
	esac
}

install_macos()
{
	INIT_SCRIPT_SRC="$EXEDIR/init.d/macos/zapret"

	# compile before root
	check_bins
	require_root
	check_location copy_all
	service_stop_macos
	remove_pf_zapret_hooks
	install_binaries
	check_dns
	select_ipv6
	ask_config
	service_install_macos
	macos_fw_reload_trigger_clear
	# gzip lists are incompatible with PF
	GZIP_LISTS=0 write_config_var GZIP_LISTS
	download_list
	macos_fw_reload_trigger_set
	crontab_del_quiet
	# desktop system. more likely up at daytime
	crontab_add 10 22
	service_start_macos
}


# build binaries, do not use precompiled
[ "$1" = "make" ] && FORCE_BUILD=1

umask 0022
fix_sbin_path
fsleep_setup
check_system

[ "$SYSTEM" = "macos" ] && . "$EXEDIR/init.d/macos/functions"

case $SYSTEM in
	systemd)
		install_systemd
		;;
	openrc)
		install_openrc
		;;
	linux)
		install_linux
		;;
	openwrt)
		install_openwrt
		;;
	macos)
		install_macos
		;;
esac


exitp 0
