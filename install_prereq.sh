#!/bin/sh

# install prerequisites

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
ZAPRET_BASE=${ZAPRET_BASE:-"$EXEDIR"}
ZAPRET_RW=${ZAPRET_RW:-"$ZAPRET_BASE"}
ZAPRET_CONFIG=${ZAPRET_CONFIG:-"$ZAPRET_RW/config"}
ZAPRET_CONFIG_DEFAULT="$ZAPRET_BASE/config.default"

[ -f "$ZAPRET_CONFIG" ] || {
	ZAPRET_CONFIG_DIR="$(dirname "$ZAPRET_CONFIG")"
	[ -d "$ZAPRET_CONFIG_DIR" ] || mkdir -p "$ZAPRET_CONFIG_DIR"
	cp "$ZAPRET_CONFIG_DEFAULT" "$ZAPRET_CONFIG"
}

. "$ZAPRET_CONFIG"
. "$ZAPRET_BASE/common/base.sh"
. "$ZAPRET_BASE/common/elevate.sh"
. "$ZAPRET_BASE/common/fwtype.sh"
. "$ZAPRET_BASE/common/dialog.sh"
. "$ZAPRET_BASE/common/installer.sh"
. "$ZAPRET_BASE/common/ipt.sh"

umask 0022
fix_sbin_path
fsleep_setup
check_system accept_unknown_rc
[ $UNAME = "Linux" ] || {
	echo no prerequisites required for $UNAME
	exitp 0
}
require_root

case $UNAME in
	Linux)
		select_fwtype
		case $SYSTEM in
			openwrt)
				select_ipv6
				check_prerequisites_openwrt
				;;
			*)
				check_prerequisites_linux
				;;
		esac
		;;
esac

exitp 0
