find_hostlists()
{
	[ -n "$HOSTLIST_BASE" ] || HOSTLIST_BASE="$ZAPRET_BASE/ipset"

	HOSTLIST="$HOSTLIST_BASE/zapret-hosts.txt.gz"
	[ -f "$HOSTLIST" ] || HOSTLIST="$HOSTLIST_BASE/zapret-hosts.txt"
	[ -f "$HOSTLIST" ] || HOSTLIST=

	HOSTLIST_USER="$HOSTLIST_BASE/zapret-hosts-user.txt.gz"
	[ -f "$HOSTLIST_USER" ] || HOSTLIST_USER="$HOSTLIST_BASE/zapret-hosts-user.txt"
	[ -f "$HOSTLIST_USER" ] || HOSTLIST_USER=

	HOSTLIST_EXCLUDE="$HOSTLIST_BASE/zapret-hosts-user-exclude.txt.gz"
	[ -f "$HOSTLIST_EXCLUDE" ] || HOSTLIST_EXCLUDE="$HOSTLIST_BASE/zapret-hosts-user-exclude.txt"
	[ -f "$HOSTLIST_EXCLUDE" ] || HOSTLIST_EXCLUDE=
}

filter_apply_hostlist_target()
{
	# $1 - var name of tpws or nfqws params

	[ "$MODE_FILTER" = "hostlist" ] || return

	local HOSTLIST_BASE HOSTLIST HOSTLIST_USER HOSTLIST_EXCLUDE

	find_hostlists

	[ -n "$HOSTLIST" ] && eval $1="\"\$$1 --hostlist=$HOSTLIST\""
	[ -n "$HOSTLIST_USER" ] && eval $1="\"\$$1 --hostlist=$HOSTLIST_USER\""
	[ -n "$HOSTLIST_EXCLUDE" ] && eval $1="\"\$$1 --hostlist-exclude=$HOSTLIST_EXCLUDE\""
}
