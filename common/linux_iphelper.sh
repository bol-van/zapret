# there's no route_localnet for ipv6
# the best we can is to route to link local of the incoming interface
# OUTPUT - can DNAT to ::1
# PREROUTING - can't DNAT to ::1. can DNAT to link local of -i interface or to any global addr
# not a good idea to expose tpws to the world (bind to ::)


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
