#!/bin/sh

# install prerequisites

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
ZAPRET_CONFIG="$EXEDIR/config"
ZAPRET_BASE="$EXEDIR"

[ -f "$ZAPRET_CONFIG" ] || cp "${ZAPRET_CONFIG}.default" "$ZAPRET_CONFIG"
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
