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


# build binaries, do not use precompiled
[ "$1" = "make" ] && FORCE_BUILD=1

umask 0022
fsleep_setup
fix_sbin_path
check_system
[ $UNAME = "Linux" ] || {
	echo no prerequisites required for $SYSTEM
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
