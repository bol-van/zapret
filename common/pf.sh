PF_MAIN="/etc/pf.conf"
PF_ANCHOR_DIR="/etc/pf.anchors"
PF_ANCHOR_ZAPRET="$PF_ANCHOR_DIR/zapret"
PF_ANCHOR_ZAPRET_V4="$PF_ANCHOR_DIR/zapret-v4"
PF_ANCHOR_ZAPRET_V6="$PF_ANCHOR_DIR/zapret-v6"

std_ports

pf_anchor_root_reload()
{
	echo reloading PF root anchor
	pfctl -qf "$PF_MAIN"
}

pf_anchor_root()
{
	local patch
	[ -f "$PF_MAIN" ] && {
		grep -q '^rdr-anchor "zapret"$' "$PF_MAIN" || {
			echo patching rdr-anchor in $PF_MAIN
			patch=1
			sed -i '' -e '/^rdr-anchor "com\.apple\/\*"$/i \
rdr-anchor "zapret"
' $PF_MAIN
		}
		grep -q '^anchor "zapret"$' "$PF_MAIN" || {
			echo patching anchor in $PF_MAIN
			patch=1
			sed -i '' -e '/^anchor "com\.apple\/\*"$/i \
anchor "zapret"
' $PF_MAIN
		}
		grep -q "^set limit table-entries" "$PF_MAIN" || {
			echo patching table-entries limit
			patch=1
			sed -i '' -e '/^scrub-anchor "com\.apple\/\*"$/i \
set limit table-entries 5000000
' $PF_MAIN
		}

		grep -q '^anchor "zapret"$' "$PF_MAIN" &&
		grep -q '^rdr-anchor "zapret"$' "$PF_MAIN" &&
		grep -q '^set limit table-entries' "$PF_MAIN" && {
			if [ -n "$patch" ]; then
				echo successfully patched $PF_MAIN
				pf_anchor_root_reload
			else
				echo successfully checked zapret anchors in $PF_MAIN
			fi
			return 0
		}
	}
	echo ----------------------------------
	echo Automatic $PF_MAIN patching failed. You must apply root anchors manually in your PF config.
	echo rdr-anchor \"zapret\"
	echo anchor \"zapret\"
	echo ----------------------------------
	return 1
}
pf_anchor_root_del()
{
	sed -i '' -e '/^anchor "zapret"$/d' -e '/^rdr-anchor "zapret"$/d' -e '/^set limit table-entries/d' "$PF_MAIN"
}

pf_anchor_zapret()
{
	[ "$DISABLE_IPV4" = "1" ] || {
		if [ -f "$ZIPLIST_EXCLUDE" ]; then
			echo "table <nozapret> persist file \"$ZIPLIST_EXCLUDE\""
		else
			echo "table <nozapret> persist"
		fi
	}
	[ "$DISABLE_IPV6" = "1" ] || {
		if [ -f "$ZIPLIST_EXCLUDE6" ]; then
			echo "table <nozapret6> persist file \"$ZIPLIST_EXCLUDE6\""
		else
			echo "table <nozapret6> persist"
		fi
	}
	[ "$DISABLE_IPV4" = "1" ] || echo "rdr-anchor \"/zapret-v4\" inet to !<nozapret>"
	[ "$DISABLE_IPV6" = "1" ] || echo "rdr-anchor \"/zapret-v6\" inet6 to !<nozapret6>"
	[ "$DISABLE_IPV4" = "1" ] || echo "anchor \"/zapret-v4\" inet to !<nozapret>"
	[ "$DISABLE_IPV6" = "1" ] || echo "anchor \"/zapret-v6\" inet6 to !<nozapret6>"
}
pf_anchor_zapret_tables()
{
	# $1 - variable to receive applied table names
	# $2/$3 $4/$5 ...  table_name/table_file
	local tblv=$1
	local _tbl

	shift
	[ "$MODE_FILTER" = "ipset" ] &&
	{
		while [ -n "$1" ] && [ -n "$2" ] ; do
			[ -f "$2" ] && {
				echo "table <$1> file \"$2\""
				_tbl="$_tbl<$1> "
			}
			shift
			shift
		done
	}
	[ -n "$_tbl" ] || _tbl="any"

	eval $tblv="\"\$_tbl\""
}
pf_nat_reorder_rules()
{
	# this is dirty hack to move rdr above route-to
        # use only first word as a key and preserve order within a single key
	sort -srfk 1,1
}

pf_anchor_zapret_v4_tpws()
{
	# $1 - tpws listen port
	# $2 - rdr ports

	local rule port="{$2}"
	for lan in $IFACE_LAN; do
		for t in $tbl; do
			 echo "rdr on $lan inet proto tcp from any to $t port $port -> 127.0.0.1 port $1"
		done
	done
	echo "rdr on lo0 inet proto tcp from !127.0.0.0/8 to any port $port -> 127.0.0.1 port $1"
	for t in $tbl; do
		rule="route-to (lo0 127.0.0.1) inet proto tcp from !127.0.0.0/8 to $t port $port user { >root }"
		if [ -n "$IFACE_WAN" ] ; then
			for wan in $IFACE_WAN; do
				echo "pass out on $wan $rule"
			done
		else
			echo "pass out $rule"
		fi
	done
}

pf_anchor_zapret_v4()
{
	local tbl port
	[ "$DISABLE_IPV4" = "1" ] || {
		{
			pf_anchor_zapret_tables tbl zapret-user "$ZIPLIST_USER" zapret "$ZIPLIST"
			custom_runner zapret_custom_firewall_v4
			[ "$TPWS_ENABLE" = 1 -a -n "$TPWS_PORTS" ] && pf_anchor_zapret_v4_tpws $TPPORT "$TPWS_PORTS_IPT"
		} | pf_nat_reorder_rules
	}
}
pf_anchor_zapret_v6_tpws()
{
	# $1 - tpws listen port
	# $2 - rdr ports

	local rule LL_LAN port="{$2}"

	# LAN link local is only for router
	for lan in $IFACE_LAN; do
		LL_LAN=$(get_ipv6_linklocal $lan)
		[ -n "$LL_LAN" ] && {
			for t in $tbl; do
				echo "rdr on $lan inet6 proto tcp from any to $t port $port -> $LL_LAN port $1"
			done
		}
	done
	echo "rdr on lo0 inet6 proto tcp from !::1 to any port $port -> fe80::1 port $1"
	for t in $tbl; do
		rule="route-to (lo0 fe80::1) inet6 proto tcp from !::1 to $t port $port user { >root }"
		if [ -n "${IFACE_WAN6:-$IFACE_WAN}" ] ; then
			for wan in ${IFACE_WAN6:-$IFACE_WAN}; do
				echo "pass out on $wan $rule"
			done
		else
			echo "pass out $rule"
		fi
	done
}
pf_anchor_zapret_v6()
{
	local tbl port
	[ "$DISABLE_IPV6" = "1" ] || {
		{
			pf_anchor_zapret_tables tbl zapret-user "$ZIPLIST_USER" zapret "$ZIPLIST"
			custom_runner zapret_custom_firewall_v6
			[ "$TPWS_ENABLE" = 1 -a -n "$TPWS_PORTS_IPT" ] && pf_anchor_zapret_v6_tpws $TPPORT "$TPWS_PORTS_IPT"
		} | pf_nat_reorder_rules
	}
}

pf_anchors_create()
{
	wait_lan_ll
	pf_anchor_zapret >"$PF_ANCHOR_ZAPRET"
	pf_anchor_zapret_v4 >"$PF_ANCHOR_ZAPRET_V4"
	pf_anchor_zapret_v6 >"$PF_ANCHOR_ZAPRET_V6"
}
pf_anchors_del()
{
	rm -f "$PF_ANCHOR_ZAPRET" "$PF_ANCHOR_ZAPRET_V4" "$PF_ANCHOR_ZAPRET_V6"
}
pf_anchors_load()
{
	echo loading zapret anchor from "$PF_ANCHOR_ZAPRET"
	pfctl -qa zapret -f "$PF_ANCHOR_ZAPRET" || {
		echo error loading zapret anchor
		return 1
	}
	if [ "$DISABLE_IPV4" = "1" ]; then
		echo clearing zapret-v4 anchor
		pfctl -qa zapret-v4 -F all 2>/dev/null
	else
		echo loading zapret-v4 anchor from "$PF_ANCHOR_ZAPRET_V4"
		pfctl -qa zapret-v4 -f "$PF_ANCHOR_ZAPRET_V4" || {
			echo error loading zapret-v4 anchor
			return 1
		}
	fi
	if [ "$DISABLE_IPV6" = "1" ]; then
		echo clearing zapret-v6 anchor
		pfctl -qa zapret-v6 -F all 2>/dev/null
	else
		echo loading zapret-v6 anchor from "$PF_ANCHOR_ZAPRET_V6"
		pfctl -qa zapret-v6 -f "$PF_ANCHOR_ZAPRET_V6" || {
			echo error loading zapret-v6 anchor
			return 1
		}
	fi
	echo successfully loaded PF anchors
	return 0
}
pf_anchors_clear()
{
	echo clearing zapret anchors
	pfctl -qa zapret-v4 -F all 2>/dev/null
	pfctl -qa zapret-v6 -F all 2>/dev/null
	pfctl -qa zapret -F all 2>/dev/null
}
pf_enable()
{
	echo enabling PF
	pfctl -qe
}
pf_table_reload()
{
	echo reloading zapret tables
	[ "$DISABLE_IPV4" = "1" ] || pfctl -qTl -a zapret-v4 -f "$PF_ANCHOR_ZAPRET_V4"
	[ "$DISABLE_IPV6" = "1" ] || pfctl -qTl -a zapret-v6 -f "$PF_ANCHOR_ZAPRET_V6"
	pfctl -qTl -a zapret -f "$PF_ANCHOR_ZAPRET"
}
