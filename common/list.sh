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

	HOSTLIST_AUTO="$HOSTLIST_BASE/zapret-hosts-auto.txt"
}

filter_apply_autohostlist_target()
{
	# $1 - var name of tpws or nfqws params
	
	local parm1="${AUTOHOSTLIST_FAIL_THRESHOLD:+--hostlist-auto-fail-threshold=$AUTOHOSTLIST_FAIL_THRESHOLD}"
	local parm2="${AUTOHOSTLIST_FAIL_TIME:+--hostlist-auto-fail-time=$AUTOHOSTLIST_FAIL_TIME}"
	local parm3
	[ "$MODE" = "tpws" -o "$MODE" = "tpws-socks" ] || parm3="${AUTOHOSTLIST_RETRANS_THRESHOLD:+--hostlist-auto-retrans-threshold=$AUTOHOSTLIST_RETRANS_THRESHOLD}"
	eval $1="\"\$$1 --hostlist-auto=$HOSTLIST_AUTO $parm1 $parm2 $parm3\""
}

filter_apply_hostlist_target()
{
	# $1 - var name of tpws or nfqws params

	[ "$MODE_FILTER" = "hostlist" -o "$MODE_FILTER" = "autohostlist" ] || return

	local HOSTLIST_BASE HOSTLIST HOSTLIST_USER HOSTLIST_EXCLUDE

	find_hostlists

	[ -n "$HOSTLIST" ] && eval $1="\"\$$1 --hostlist=$HOSTLIST\""
	[ -n "$HOSTLIST_USER" ] && eval $1="\"\$$1 --hostlist=$HOSTLIST_USER\""
	[ -n "$HOSTLIST_EXCLUDE" ] && eval $1="\"\$$1 --hostlist-exclude=$HOSTLIST_EXCLUDE\""
	[ "$MODE_FILTER" = "autohostlist" ] && filter_apply_autohostlist_target $1
}
