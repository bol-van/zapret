readonly HOSTLIST_MARKER="<HOSTLIST>"

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
	HOSTLIST_AUTO_DEBUGLOG="$HOSTLIST_BASE/zapret-hosts-auto-debug.log"
}

filter_apply_hostlist_target()
{
	# $1 - var name of tpws or nfqws params

	local v parm parm1 parm2 parm3 parm4 parm5 parm6 parm7
	eval v="\$$1"
	contains "$v" "$HOSTLIST_MARKER" &&
	{
		[ "$MODE_FILTER" = hostlist -o "$MODE_FILTER" = autohostlist ] &&
		{
			find_hostlists
			parm1="${HOSTLIST_USER:+--hostlist=$HOSTLIST_USER}"
			parm2="${HOSTLIST:+--hostlist=$HOSTLIST}"
			parm3="${HOSTLIST_EXCLUDE:+--hostlist-exclude=$HOSTLIST_EXCLUDE}"
			[ "$MODE_FILTER" = autohostlist ] &&
			{
				parm4="--hostlist-auto=$HOSTLIST_AUTO"
				parm5="${AUTOHOSTLIST_FAIL_THRESHOLD:+--hostlist-auto-fail-threshold=$AUTOHOSTLIST_FAIL_THRESHOLD}"
				parm6="${AUTOHOSTLIST_FAIL_TIME:+--hostlist-auto-fail-time=$AUTOHOSTLIST_FAIL_TIME}"
				parm7="${AUTOHOSTLIST_RETRANS_THRESHOLD:+--hostlist-auto-retrans-threshold=$AUTOHOSTLIST_RETRANS_THRESHOLD}"
			}
			parm="$parm1${parm2:+ $parm2}${parm3:+ $parm3}${parm4:+ $parm4}${parm5:+ $parm5}${parm6:+ $parm6}${parm7:+ $parm7}"
		}
		v="$(replace_str $HOSTLIST_MARKER "$parm" "$v")"
		[ "$MODE_FILTER" = autohostlist -a "$AUTOHOSTLIST_DEBUGLOG" = 1 ] && {
			v="$v --hostlist-auto-debug=$HOSTLIST_AUTO_DEBUGLOG"
		}
		eval $1=\""$v"\"
	}
}
