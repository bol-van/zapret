[ -n "$ZAPRET_NFT_TABLE" ] || ZAPRET_NFT_TABLE=zapret

# required for : nft -f -
create_dev_stdin

nft_create_table()
{
	nft add table inet $ZAPRET_NFT_TABLE
}
nft_del_table()
{
	nft delete table inet $ZAPRET_NFT_TABLE 2>/dev/null
}
nft_list_table()
{
	nft -t list table inet $ZAPRET_NFT_TABLE
}

nft_create_set()
{
	# $1 - set name
	# $2 - params
	nft create set inet $ZAPRET_NFT_TABLE $1 "{ $2 }" 2>/dev/null
}
nft_del_set()
{
	# $1 - set name
	nft delete set inet $ZAPRET_NFT_TABLE $1
}
nft_flush_set()
{
	# $1 - set name
	nft flush set inet $ZAPRET_NFT_TABLE $1
}
nft_set_exists()
{
	# $1 - set name
	nft -t list set inet $ZAPRET_NFT_TABLE $1 2>/dev/null >/dev/null
}

nft_del_all_chains_from_table()
{
	# $1 - table_name with or without family

	# delete all chains with possible references to each other
	# cannot just delete all in the list because of references
	# avoid infinite loops
	local chains deleted=1 error=1
	while [ -n "$deleted" -a -n "$error" ]; do
		chains=$(nft -t list table $1 2>/dev/null | sed -nre "s/^[ 	]*chain ([^ ]+) \{/\1/p" | xargs)
		[ -n "$chains" ] || break
		deleted=
		error=
		for chain in $chains; do
			if nft delete chain $1 $chain 2>/dev/null; then
				deleted=1
			else
				error=1
			fi
		done
	done
}

nft_del_chains()
{
	nft_del_all_chains_from_table "inet $ZAPRET_NFT_TABLE"
}
nft_create_chains()
{
cat << EOF | nft -f -
	add chain inet $ZAPRET_NFT_TABLE dnat_output { type nat hook output priority -101; }
	flush chain inet $ZAPRET_NFT_TABLE dnat_output
	add chain inet $ZAPRET_NFT_TABLE dnat_pre { type nat hook prerouting priority -101; }
	flush chain inet $ZAPRET_NFT_TABLE dnat_pre
	add chain inet $ZAPRET_NFT_TABLE forward { type filter hook forward priority -1; }
	flush chain inet $ZAPRET_NFT_TABLE forward
	add chain inet $ZAPRET_NFT_TABLE input { type filter hook input priority -1; }
	flush chain inet $ZAPRET_NFT_TABLE input
	add chain inet $ZAPRET_NFT_TABLE flow_offload
	flush chain inet $ZAPRET_NFT_TABLE flow_offload
	add chain inet $ZAPRET_NFT_TABLE localnet_protect
	flush chain inet $ZAPRET_NFT_TABLE localnet_protect
	add rule inet  $ZAPRET_NFT_TABLE localnet_protect ip daddr $TPWS_LOCALHOST4 return comment "route_localnet allow access to tpws"
	add rule inet  $ZAPRET_NFT_TABLE localnet_protect ip daddr 127.0.0.0/8 drop comment "route_localnet remote access protection"
	add rule inet  $ZAPRET_NFT_TABLE input iifname != lo jump localnet_protect
	add chain inet $ZAPRET_NFT_TABLE postrouting { type filter hook postrouting priority -151; }
	flush chain inet $ZAPRET_NFT_TABLE postrouting
	add set inet $ZAPRET_NFT_TABLE lanif { type ifname; }
	add set inet $ZAPRET_NFT_TABLE wanif { type ifname; }
	add set inet $ZAPRET_NFT_TABLE wanif6 { type ifname; }
EOF
}
nft_del_flowtable()
{
	nft delete flowtable inet $ZAPRET_NFT_TABLE ft 2>/dev/null
}
nft_create_or_update_flowtable()
{
	# $1 = flags ('offload' for hw offload)
	# $2,$3,$4,... - interfaces
	# can be called multiple times to add interfaces. interfaces can only be added , not removed
	local flags=$1 devices
	shift
	make_comma_list devices "$@"
	[ -n "$devices" ] && devices="devices={$devices};"
	[ -n "$flags" ] && flags="flags $flags;"
	nft add flowtable inet $ZAPRET_NFT_TABLE ft "{ hook ingress priority -1; $flags $devices }"
}
nft_flush_ifsets()
{
cat << EOF | nft -f -  2>/dev/null
	flush set inet $ZAPRET_NFT_TABLE lanif
	flush set inet $ZAPRET_NFT_TABLE wanif
	flush set inet $ZAPRET_NFT_TABLE wanif6
EOF
}
nft_list_ifsets()
{
	nft list set inet $ZAPRET_NFT_TABLE lanif
	nft list set inet $ZAPRET_NFT_TABLE wanif
	nft list set inet $ZAPRET_NFT_TABLE wanif6
	nft list flowtable inet $ZAPRET_NFT_TABLE ft
}

nft_create_firewall()
{
	nft_create_table
	nft_del_flowtable
	nft_create_chains
}
nft_del_firewall()
{
	nft_del_chains
	nft_del_flowtable
	nft_flush_ifsets
}

nft_add_rule()
{
	# $1 - chain
	# $2,$3,... - rule(s)
	local chain="$1"
	shift
	nft add rule inet $ZAPRET_NFT_TABLE $chain "$@"
}
nft_add_set_elements()
{
	# $1 - set name
	# $2,$3,... - element(s)
	local set="$1" elements
	shift
	make_comma_list elements "$@"
	[ -z "$elements" ] || nft add element inet $ZAPRET_NFT_TABLE $set "{ $elements }"
}
nft_reverse_nfqws_rule()
{
	echo "$@" | sed -e 's/oifname /iifname /g' -e 's/dport /sport /g' -e 's/daddr /saddr /g' -e 's/ct original /ct reply /g' -e "s/mark and $DESYNC_MARK == 0//g"
}
nft_clean_nfqws_rule()
{
	echo "$@" | sed -e "s/mark and $DESYNC_MARK == 0//g"
}
nft_add_nfqws_flow_exempt_rule()
{
	# $1 - rule (must be all filters in one var)
	nft_add_rule flow_offload $(nft_clean_nfqws_rule $1) return comment \"direct flow offloading exemption\"
	nft_add_rule flow_offload $(nft_reverse_nfqws_rule $1) return comment \"reverse flow offloading exemption\"
}

nft_hw_offload_supported()
{
	# $1,$2,... - interface names
	local devices res=1
	make_comma_list devices "$@"
	[ -n "$devices" ] && devices="devices={$devices};"
	nft add table ${ZAPRET_NFT_TABLE}_test && nft add flowtable ${ZAPRET_NFT_TABLE}_test ft "{ flags offload; $devices }" 2>/dev/null && res=0
	nft delete table ${ZAPRET_NFT_TABLE}_test 2>/dev/null
	return $res
}

nft_apply_flow_offloading()
{
	# ft can be absent
	nft_add_rule flow_offload meta l4proto "{ tcp, udp }" flow add @ft 2>/dev/null && nft_add_rule forward jump flow_offload
}



nft_filter_apply_port_target()
{
	# $1 - var name of nftables filter
	local f
	if [ "$MODE_HTTP" = "1" ] && [ "$MODE_HTTPS" = "1" ]; then
		f="tcp dport {80,443}"
	elif [ "$MODE_HTTPS" = "1" ]; then
		f="tcp dport 443"
	elif [ "$MODE_HTTP" = "1" ]; then
		f="tcp dport 80"
	else
		echo WARNING !!! HTTP and HTTPS are both disabled
	fi
	eval $1="\"\$$1 $f\""
}
nft_filter_apply_ipset_target4()
{
	# $1 - var name of ipv4 nftables filter
	if [ "$MODE_FILTER" = "ipset" ]; then
		eval $1="\"\$$1 ip daddr @zapret\""
	fi
}
nft_filter_apply_ipset_target6()
{
	# $1 - var name of ipv6 nftables filter
	if [ "$MODE_FILTER" = "ipset" ]; then
		eval $1="\"\$$1 ip6 daddr @zapret6\""
	fi
}
nft_filter_apply_ipset_target()
{
	# $1 - var name of ipv4 nftables filter
	# $2 - var name of ipv6 nftables filter
	nft_filter_apply_ipset_target4 $1
	nft_filter_apply_ipset_target6 $2
}

nft_only()
{
	linux_fwtype

	case "$FWTYPE" in
		nftables)
			"$@"
			;;
	esac
}

zapret_reload_ifsets()
{
	nft_only nft_create_table ; nft_fill_ifsets
	return 0
}
zapret_list_ifsets()
{
	nft_only nft_list_ifsets
	return 0
}
zapret_list_table()
{
	nft_only nft_list_table
	return 0
}

zapret_apply_firewall_nft()
{
	echo Applying nftables

	local mode="${MODE_OVERRIDE:-$MODE}"

	[ "$mode" = "tpws-socks" ] && return 0

	local first_packet_only="ct original packets 1-4"
	local desync="mark and $DESYNC_MARK == 0"
	local f4 f6 qn qns qn6 qns6

	create_ipset no-update
	nft_create_firewall
	nft_fill_ifsets

	case "$mode" in
		tpws)
			if [ ! "$MODE_HTTP" = "1" ] && [ ! "$MODE_HTTPS" = "1" ]; then
				echo both http and https are disabled. not applying redirection.
			else
				nft_filter_apply_port_target f4
				f6=$f4
				nft_filter_apply_ipset_target f4 f6
				nft_fw_tpws "$f4" "$f6" $TPPORT
			fi
			;;
		nfqws)
			# quite complex but we need to minimize nfqws processes to save RAM
			get_nfqws_qnums qn qns qn6 qns6
			if [ "$MODE_HTTP_KEEPALIVE" != "1" ] && [ -n "$qn" ] && [ "$qn" = "$qns" ]; then
				nft_filter_apply_port_target f4
				f4="$f4 $first_packet_only"
				nft_filter_apply_ipset_target4 f4
				nft_fw_nfqws_post4 "$f4 $desync" $qn
			else
				if [ -n "$qn" ]; then
					f4="tcp dport 80"
					[ "$MODE_HTTP_KEEPALIVE" = "1" ] || f4="$f4 $first_packet_only"
					nft_filter_apply_ipset_target4 f4
					nft_fw_nfqws_post4 "$f4 $desync" $qn
				fi
				if [ -n "$qns" ]; then
					f4="tcp dport 443 $first_packet_only"
					nft_filter_apply_ipset_target4 f4
					nft_fw_nfqws_post4 "$f4 $desync" $qns
				fi
			fi
			if [ "$MODE_HTTP_KEEPALIVE" != "1" ] && [ -n "$qn6" ] && [ "$qn6" = "$qns6" ]; then
				nft_filter_apply_port_target f6
				f6="$f6 $first_packet_only"
				nft_filter_apply_ipset_target6 f6
				nft_fw_nfqws_post6 "$f6 $desync" $qn6
			else
				if [ -n "$qn6" ]; then
					f6="tcp dport 80"
					[ "$MODE_HTTP_KEEPALIVE" = "1" ] || f6="$f6 $first_packet_only"
					nft_filter_apply_ipset_target6 f6
					nft_fw_nfqws_post6 "$f6 $desync" $qn6
				fi
				if [ -n "$qns6" ]; then
					f6="tcp dport 443 $first_packet_only"
					nft_filter_apply_ipset_target6 f6
					nft_fw_nfqws_post6 "$f6 $desync" $qns6
				fi
			fi
			;;
		custom)
	    		existf zapret_custom_firewall_nft && zapret_custom_firewall_nft
			;;
	esac

	[ "$FLOWOFFLOAD" = 'software' -o "$FLOWOFFLOAD" = 'hardware' ] && nft_apply_flow_offloading

	return 0
}
zapret_unapply_firewall_nft()
{
	echo Clearing nftables

	unprepare_route_localnet
	nft_del_firewall
	return 0
}
zapret_do_firewall_nft()
{
	# $1 - 1 - add, 0 - del

	if [ "$1" = 0 ] ; then
		zapret_unapply_firewall_nft
	else
		zapret_apply_firewall_nft
	fi
	
	return 0
}
