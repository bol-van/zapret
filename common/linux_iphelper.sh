# there's no route_localnet for ipv6
# the best we can is to route to link local of the incoming interface
# OUTPUT - can DNAT to ::1
# PREROUTING - can't DNAT to ::1. can DNAT to link local of -i interface or to any global addr
# not a good idea to expose tpws to the world (bind to ::)

# max wait time for the link local ipv6 on the LAN interface
LINKLOCAL_WAIT_SEC=${LINKLOCAL_WAIT_SEC:-5}

get_ipv6_linklocal()
{
 # $1 - interface name. if empty - any interface
 if exists ip ; then
    local dev
    [ -n "$1" ] && dev="dev $1"
    ip addr show $dev | sed -e 's/^.*inet6 \([^ ]*\)\/[0-9]* scope link.*$/\1/;t;d' | head -n 1
 else
    ifconfig $1 | sed -re 's/^.*inet6 addr: ([^ ]*)\/[0-9]* Scope:Link.*$/\1/;t;d' | head -n 1
 fi
}
get_ipv6_global()
{
 # $1 - interface name. if empty - any interface
 if exists ip ; then
    local dev
    [ -n "$1" ] && dev="dev $1"
    ip addr show $dev | sed -e 's/^.*inet6 \([^ ]*\)\/[0-9]* scope global.*$/\1/;t;d' | head -n 1
 else
    ifconfig $1 | sed -re 's/^.*inet6 addr: ([^ ]*)\/[0-9]* Scope:Global.*$/\1/;t;d' | head -n 1
 fi
}

iface_is_up()
{	
	# $1 - interface name
	[ -f /sys/class/net/$1/operstate ] || return
	local state
	read state </sys/class/net/$1/operstate
	[ "$state" != "down" ]
}
wait_ifup()
{
	# $1 - interface name
	local ct=0
	while
		iface_is_up $1 && return
		[ "$ct" -ge "$IFUP_WAIT_SEC" ] && break
		echo waiting for ifup of $1 for another $(($IFUP_WAIT_SEC - $ct)) seconds ...
		ct=$(($ct+1))
		sleep 1
	do :; done
	false
}

_dnat6_target()
{
	# $1 - interface name
	# $2 - var to store target ip6
	# get target ip address for DNAT. prefer link locals
	# tpws should be as inaccessible from outside as possible
	# link local address can appear not immediately after ifup
	# DNAT6_TARGET=- means attempt was made but address was not found (to avoid multiple re-attempts)

	local DNAT6_TARGET DVAR=DNAT6_TARGET_$1
	DVAR=$(echo $DVAR | sed 's/[^a-zA-Z0-9_]/_/g')
	eval DNAT6_TARGET="\$$DVAR"
	[ -n "$2" ] && eval $2=''
	[ -n "$DNAT6_TARGET" ] || {
		local ct=0
		while
			DNAT6_TARGET=$(get_ipv6_linklocal $1)
			[ -n "$DNAT6_TARGET" ] && break
			[ "$ct" -ge "$LINKLOCAL_WAIT_SEC" ] && break
			echo $1: waiting for the link local for another $(($LINKLOCAL_WAIT_SEC - $ct)) seconds ...
			ct=$(($ct+1))
			sleep 1
		do :; done

		[ -n "$DNAT6_TARGET" ] || {
		    	echo $1: no link local. getting global
			DNAT6_TARGET=$(get_ipv6_global $1)
			[ -n "$DNAT6_TARGET" ] || {
				echo $1: could not get any address
				DNAT6_TARGET=-
			}
		}
		eval $DVAR="$DNAT6_TARGET"
	}
	[ -n "$2" ] && eval $2="$DNAT6_TARGET"
}

_set_route_localnet()
{
	# $1 - 1 = enable, 0 = disable
	# $2,$3,... - interface names
	[ "$DISABLE_IPV4" = "1" ] || {
		local enable="$1"
		shift
		while [ -n "$1" ]; do
			sysctl -q -w net.ipv4.conf.$1.route_localnet="$enable"
			shift
		done
	}
}
prepare_route_localnet()
{
	set_route_localnet 1 "$@"
}
unprepare_route_localnet()
{
	set_route_localnet 0 "$@"
}

resolve_lower_devices()
{
	# $1 - bridge interface name
	[ -d "/sys/class/net/$1" ] && {
		find "/sys/class/net/$1" -follow -maxdepth 1 -name "lower_*" |
		{
			local l lower lowers
			while read lower; do
				lower="$(basename "$lower")"
				l="${lower#lower_*}"
				[  "$l" != "$lower" ] && append_separator_list lowers ' ' '' "$l"
			done
			printf "$lowers"
		}
	}
}

default_route_interfaces6()
{
	sed -nre 's/^00000000000000000000000000000000 00 [0-9a-f]{32} [0-9a-f]{2} [0-9a-f]{32} [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} +(.*)$/\1/p' /proc/net/ipv6_route | grep -v '^lo$' | sort -u | xargs
}

default_route_interfaces4()
{
	sed -nre 's/^([^\t]+)\t00000000\t[0-9A-F]{8}\t[0-9A-F]{4}\t[0-9]+\t[0-9]+\t[0-9]+\t00000000.*$/\1/p' /proc/net/route | sort -u | xargs
}
