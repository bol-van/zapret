exists()
{
	which "$1" >/dev/null 2>/dev/null
}
existf()
{
	type "$1" >/dev/null 2>/dev/null
}
whichq()
{
	which $1 2>/dev/null
}
exist_all()
{
	while [ -n "$1" ]; do
		exists "$1" || return 1
		shift
	done
	return 0
}
on_off_function()
{
	# $1 : function name on
	# $2 : function name off
	# $3 : 0 - off, 1 - on
	local F="$1"
	[ "$3" = "1" ] || F="$2"
	shift
	shift
	shift
	"$F" "$@"
}
contains()
{
	# check if substring $2 contains in $1
	[ "${1#*$2}" != "$1" ]
}
find_str_in_list()
{
	[ -n "$1" ] && {
		for v in $2; do
			[ "$v" = "$1" ] && return 0
		done
	}
	return 1
}
end_with_newline()
{
	local c=$(tail -c 1)
	[ "$c" = "" ]
}
make_separator_list()
{
	# $1 - var name to receive result
	# $2 - separator
	# $3,$4,... - elements
	local var="$1" sep="$2" i

	shift; shift
	while [ -n "$1" ]; do
		if [ -n "$i" ] ; then
			i=$i$sep$1
		else
			i=$1
		fi
		shift
	done
	eval $var=$i
}
make_comma_list()
{
	# $1 - var name to receive result
	# $2,$3,... - elements
	local var="$1"
	shift
	make_separator_list $var , "$@"
}

is_linked_to_busybox()
{
	local IFS F P
	
	IFS=:
	for path in $PATH; do
		F=$path/$1
		P="$(readlink $F)"
		if [ -z "$P" ] && [ -x $F ] && [ ! -L $F ]; then return 1; fi
		[ "${P%busybox*}" != "$P" ] && return
	done
}
get_dir_inode()
{
	local dir="$1"
	[ -L "$dir" ] && dir=$(readlink "$dir")
	ls -id "$dir" | awk '{print $1}'
}

linux_min_version()
{
	# $1 - major ver
	# $2 - minor ver
	local V1=$(sed -nre 's/^Linux version ([0-9]+)\.[0-9]+.*$/\1/p' /proc/version)
	local V2=$(sed -nre 's/^Linux version [0-9]+\.([0-9]+).*$/\1/p' /proc/version)
	[ -n "$V1" -a -n "$V2" ] && [ "$V1" -gt "$1" -o "$V1" -eq "$1" -a "$V2" -ge "$2" ]
}
linux_get_subsys()
{
	local INIT=$(sed 's/\x0/\n/g' /proc/1/cmdline | head -n 1)

	[ -L "$INIT" ] && INIT=$(readlink "$INIT")
	INIT=$(basename "$INIT")
	if [ -f "/etc/openwrt_release" ] && [ "$INIT" = "procd" ] ; then
		SUBSYS=openwrt
	else
		# generic linux
		SUBSYS=
	fi
}
openwrt_fw3()
{
	[ ! -x /sbin/fw4 -a -x /sbin/fw3 ]
}
openwrt_fw4()
{
	[ -x /sbin/fw4 ]
}
openwrt_fw3_integration()
{
	[ "$FWTYPE" = iptables ] && openwrt_fw3
}

create_dev_stdin()
{
	[ -e /dev/stdin ] || ln -s /proc/self/fd/0 /dev/stdin
}
