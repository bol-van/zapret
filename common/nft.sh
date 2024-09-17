[ -n "$ZAPRET_NFT_TABLE" ] || ZAPRET_NFT_TABLE=zapret
readonly nft_connbytes="ct original packets"

# required for: nft -f -
create_dev_stdin
std_ports

nft_create_table() {
	nft add table inet "$ZAPRET_NFT_TABLE"
}
nft_del_table() {
	nft delete table inet "$ZAPRET_NFT_TABLE" 2>/dev/null
}
nft_list_table() {
	nft -t list table inet "$ZAPRET_NFT_TABLE"
}

nft_create_set() {
	# $1 - set name
	# $2 - params
	nft create set inet "$ZAPRET_NFT_TABLE" "$1" "{ $2 }" 2>/dev/null
}
nft_del_set() {
	# $1 - set name
	nft delete set inet "$ZAPRET_NFT_TABLE" "$1"
}
nft_flush_set() {
	# $1 - set name
	nft flush set inet "$ZAPRET_NFT_TABLE" "$1"
}
nft_set_exists() {
	# $1 - set name
	nft -t list set inet "$ZAPRET_NFT_TABLE" "$1" 2>/dev/null >/dev/null
}
nft_flush_chain() {
	# $1 - chain name
	nft flush chain inet "$ZAPRET_NFT_TABLE" "$1"
}

nft_del_all_chains_from_table() {
	# $1 - table_name with or without family

	# delete all chains with possible references to each other
	# cannot just delete all in the list because of references
	# avoid infinite loops
	local chains deleted=1 error=1
	while [ -n "$deleted" -a -n "$error" ]; do
		chains=$(nft -t list table "$1" 2>/dev/null | sed -nre "s/^[ 	]*chain ([^ ]+) \{/\1/p" | xargs)
		[ -n "$chains" ] || break
		deleted=
		error=
		for chain in $chains; do
			if nft delete chain "$1" "$chain" 2>/dev/null; then
				deleted=1
			else
				error=1
			fi
		done
	done
}

nft_create_chains() {
	cat <<EOF | nft -f -
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
	add rule inet  $ZAPRET_NFT_TABLE input iif != lo jump localnet_protect
	add chain inet $ZAPRET_NFT_TABLE postrouting { type filter hook postrouting priority 99; }
	flush chain inet $ZAPRET_NFT_TABLE postrouting
	add chain inet $ZAPRET_NFT_TABLE postnat { type filter hook postrouting priority 101; }
	flush chain inet $ZAPRET_NFT_TABLE postnat
	add chain inet $ZAPRET_NFT_TABLE prerouting { type filter hook prerouting priority -99; }
	flush chain inet $ZAPRET_NFT_TABLE prerouting
	add chain inet $ZAPRET_NFT_TABLE prenat { type filter hook prerouting priority -101; }
	flush chain inet $ZAPRET_NFT_TABLE prenat
	add chain inet $ZAPRET_NFT_TABLE predefrag { type filter hook output priority -401; }
	flush chain inet $ZAPRET_NFT_TABLE predefrag
	add chain inet $ZAPRET_NFT_TABLE predefrag_nfqws
	flush chain inet $ZAPRET_NFT_TABLE predefrag_nfqws
	add rule inet $ZAPRET_NFT_TABLE predefrag mark and $DESYNC_MARK !=0 jump predefrag_nfqws comment "nfqws generated : avoid drop by INVALID conntrack state"
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws mark and $DESYNC_MARK_POSTNAT !=0 notrack comment "postnat traffic"
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws ip frag-off != 0 notrack comment "ipfrag"
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws exthdr frag exists notrack comment "ipfrag"
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws tcp flags ! syn,rst,ack notrack comment "datanoack"
	add set inet $ZAPRET_NFT_TABLE lanif { type ifname; }
	add set inet $ZAPRET_NFT_TABLE wanif { type ifname; }
	add set inet $ZAPRET_NFT_TABLE wanif6 { type ifname; }
	add map inet $ZAPRET_NFT_TABLE link_local { type ifname : ipv6_addr; }
EOF
	[ -n "$POSTNAT_ALL" ] && {
		nft_flush_chain predefrag_nfqws
		nft_add_rule predefrag_nfqws notrack comment \"do not track nfqws generated packets to avoid NAT tampering and defragmentation\"
	}
}
nft_del_chains() {
	# do not delete all chains because of additional user hooks
	# they must be inside zapret table to use nfsets

	cat <<EOF | nft -f - 2>/dev/null
	delete chain inet $ZAPRET_NFT_TABLE dnat_output
	delete chain inet $ZAPRET_NFT_TABLE dnat_pre
	delete chain inet $ZAPRET_NFT_TABLE forward
	delete chain inet $ZAPRET_NFT_TABLE input
	delete chain inet $ZAPRET_NFT_TABLE postrouting
	delete chain inet $ZAPRET_NFT_TABLE postnat
	delete chain inet $ZAPRET_NFT_TABLE prerouting
	delete chain inet $ZAPRET_NFT_TABLE prenat
	delete chain inet $ZAPRET_NFT_TABLE predefrag
	delete chain inet $ZAPRET_NFT_TABLE predefrag_nfqws
	delete chain inet $ZAPRET_NFT_TABLE flow_offload
	delete chain inet $ZAPRET_NFT_TABLE localnet_protect
EOF
	# unfortunately this approach breaks udp desync of the connection initiating packet (new, first one)
	#	delete chain inet $ZAPRET_NFT_TABLE predefrag
}
nft_del_flowtable() {
	nft delete flowtable inet "$ZAPRET_NFT_TABLE" ft 2>/dev/null
}
nft_create_or_update_flowtable() {
	# $1 = flags ('offload' for hw offload)
	# $2,$3,$4,... - interfaces
	# can be called multiple times to add interfaces. interfaces can only be added, not removed
	local flags=$1 devices makelist
	shift
	# warning ! nft versions at least up to 1.0.1 do not allow interface names starting with digit in flowtable and do not allow quoting
	# warning ! OpenWrt fixes this in post-21.x snapshots with special nft patch
	# warning ! in traditional Linux distros nft is unpatched and will fail with quoted interface definitions if unfixed
	[ -n "$flags" ] && flags="flags $flags;"
	for makelist in make_quoted_comma_list make_comma_list; do
		$makelist devices "$@"
		[ -n "$devices" ] && devices="devices={$devices};"
		nft add flowtable inet "$ZAPRET_NFT_TABLE" ft "{ hook ingress priority -1; $flags $devices }" && break
	done
}
nft_flush_ifsets() {
	cat <<EOF | nft -f - 2>/dev/null
	flush set inet $ZAPRET_NFT_TABLE lanif
	flush set inet $ZAPRET_NFT_TABLE wanif
	flush set inet $ZAPRET_NFT_TABLE wanif6
	flush map inet $ZAPRET_NFT_TABLE link_local
EOF
}
nft_flush_link_local() {
	nft flush map inet "$ZAPRET_NFT_TABLE" link_local 2>/dev/null
}
nft_list_ifsets() {
	nft list set inet "$ZAPRET_NFT_TABLE" lanif
	nft list set inet "$ZAPRET_NFT_TABLE" wanif
	nft list set inet "$ZAPRET_NFT_TABLE" wanif6
	nft list map inet "$ZAPRET_NFT_TABLE" link_local
	nft list flowtable inet "$ZAPRET_NFT_TABLE" ft 2>/dev/null
}

nft_create_firewall() {
	nft_create_table
	nft_del_flowtable
	nft_flush_link_local
	nft_create_chains
}
nft_del_firewall() {
	nft_del_chains
	nft_del_flowtable
	nft_flush_link_local
	# leave ifsets and IP sets because they may be used by custom rules
}

nft_add_rule() {
	# $1 - chain
	# $2,$3,... - rule(s)
	local chain="$1"
	shift
	nft add rule inet "$ZAPRET_NFT_TABLE" "$chain" "$@"
}
nft_add_set_element() {
	# $1 - set or map name
	# $2 - element
	[ -z "$2" ] || nft add element inet "$ZAPRET_NFT_TABLE" "$1" "{ $2 }"
}
nft_add_set_elements() {
	# $1 - set or map name
	# $2,$3,... - element(s)
	local set="$1" elements
	shift
	make_comma_list elements "$@"
	nft_add_set_element "$set" "$elements"
}
nft_reverse_nfqws_rule() {
	echo "$@" | sed -e 's/oifname /iifname /g' -e 's/dport /sport /g' -e 's/daddr /saddr /g' -e 's/ct original /ct reply /g' -e "s/mark and $DESYNC_MARK == 0//g"
}
nft_clean_nfqws_rule() {
	echo "$@" | sed -e "s/mark and $DESYNC_MARK == 0//g" -e "s/oifname @wanif6//g" -e "s/oifname @wanif//g"
}
nft_add_nfqws_flow_exempt_rule() {
	# $1 - rule (must be all filters in one var)
	nft_add_rule flow_offload $(nft_clean_nfqws_rule "$1") return comment \"direct flow offloading exemption\"
	# do not need this because of oifname @wanif/@wanif6 filter in forward chain
	#nft_add_rule flow_offload $(nft_reverse_nfqws_rule $1) return comment \"reverse flow offloading exemption\"
}
nft_add_flow_offload_exemption() {
	# "$1" - rule for ipv4
	# "$2" - rule for ipv6
	# "$3" - comment
	[ "$DISABLE_IPV4" = "1" -o -z "$1" ] || nft_add_rule flow_offload oifname @wanif "$1" ip daddr != @nozapret return comment \""$3"\"
	[ "$DISABLE_IPV6" = "1" -o -z "$2" ] || nft_add_rule flow_offload oifname @wanif6 "$2" ip6 daddr != @nozapret6 return comment \""$3"\"
}

nft_hw_offload_supported() {
	# $1,$2,... - interface names
	local devices res=1
	make_quoted_comma_list devices "$@"
	[ -n "$devices" ] && devices="devices={$devices};"
	nft add table "${ZAPRET_NFT_TABLE}"_test && nft add flowtable "${ZAPRET_NFT_TABLE}"_test ft "{ flags offload; $devices }" 2>/dev/null && res=0
	nft delete table "${ZAPRET_NFT_TABLE}"_test 2>/dev/null
	return $res
}

nft_hw_offload_find_supported() {
	# $1,$2,... - interface names
	local supported_list
	while [ -n "$1" ]; do
		nft_hw_offload_supported "$1" && append_separator_list supported_list ' ' '' "$1"
		shift
	done
	echo "$supported_list"
}

nft_apply_flow_offloading() {
	# ft can be absent
	nft_add_rule flow_offload meta l4proto "{ tcp, udp }" flow add @ft 2>/dev/null && {
		nft_add_rule flow_offload meta l4proto "{ tcp, udp }" counter comment \"if offload works here must not be too much traffic\"
		# allow only outgoing packets to initiate flow offload
		nft_add_rule forward oifname @wanif jump flow_offload
		nft_add_rule forward oifname @wanif6 jump flow_offload
	}
}

nft_filter_apply_port_target() {
	# $1 - var name of nftables filter
	local f
	if [ "$MODE_HTTP" = "1" ] && [ "$MODE_HTTPS" = "1" ]; then
		f="tcp dport {$HTTP_PORTS,$HTTPS_PORTS}"
	elif [ "$MODE_HTTPS" = "1" ]; then
		f="tcp dport {$HTTPS_PORTS}"
	elif [ "$MODE_HTTP" = "1" ]; then
		f="tcp dport {$HTTP_PORTS}"
	else
		echo WARNING !!! HTTP and HTTPS are both disabled
	fi
	eval "$1"="\"\$$1 $f\""
}
nft_filter_apply_port_target_quic() {
	# $1 - var name of nftables filter
	local f
	f="udp dport {$QUIC_PORTS}"
	eval "$1"="\"\$$1 $f\""
}
nft_filter_apply_ipset_target4() {
	# $1 - var name of ipv4 nftables filter
	if [ "$MODE_FILTER" = "ipset" ]; then
		eval "$1"="\"\$$1 ip daddr @zapret\""
	fi
}
nft_filter_apply_ipset_target6() {
	# $1 - var name of ipv6 nftables filter
	if [ "$MODE_FILTER" = "ipset" ]; then
		eval "$1"="\"\$$1 ip6 daddr @zapret6\""
	fi
}
nft_filter_apply_ipset_target() {
	# $1 - var name of ipv4 nftables filter
	# $2 - var name of ipv6 nftables filter
	nft_filter_apply_ipset_target4 "$1"
	nft_filter_apply_ipset_target6 "$2"
}

nft_script_add_ifset_element() {
	# $1 - set name
	# $2 - space separated elements
	local elements
	[ -n "$2" ] && {
		make_quoted_comma_list elements "$2"
		script="${script}
add element inet $ZAPRET_NFT_TABLE $1 { $elements }"
	}
}
nft_fill_ifsets() {
	# $1 - space separated LAN interface names
	# $2 - space separated WAN interface names
	# $3 - space separated WAN6 interface names
	# 4,5,6 is needed for PPPoE+OpenWrt case. looks like it's not easily possible to resolve Ethernet device behind a PPPoE interface
	# $4 - space separated LAN physical interface names (optional)
	# $5 - space separated WAN physical interface names (optional)
	# $6 - space separated WAN6 physical interface names (optional)

	local script i j ALLDEVS devs

	# if large sets exist nft works very ineffectively
	# looks like it analyzes the whole table blob to find required data pieces
	# calling all in one shot helps not to waste cpu time many times

	script="flush set inet $ZAPRET_NFT_TABLE wanif
flush set inet $ZAPRET_NFT_TABLE wanif6
flush set inet $ZAPRET_NFT_TABLE lanif"

	[ "$DISABLE_IPV4" = "1" ] || nft_script_add_ifset_element wanif "$2"
	[ "$DISABLE_IPV6" = "1" ] || nft_script_add_ifset_element wanif6 "$3"
	nft_script_add_ifset_element lanif "$1"

	echo "$script" | nft -f -

	case "$FLOWOFFLOAD" in
	software)
		ALLDEVS=$(unique "$1" "$2" "$3")
		# unbound flowtable may cause error in older nft version
		nft_create_or_update_flowtable '' "$ALLDEVS" 2>/dev/null
		;;
	hardware)
		ALLDEVS=$(unique "$1" "$2" "$3" "$4" "$5" "$6")
		# first create unbound flowtable. may cause error in older nft version
		nft_create_or_update_flowtable 'offload' 2>/dev/null
		# then add elements. some of them can cause error because unsupported
		for i in $ALLDEVS; do
			if nft_hw_offload_supported "$i"; then
				nft_create_or_update_flowtable 'offload' "$i"
			else
				# bridge members must be added instead of the bridge itself
				# some members may not support hw offload. example: lan1 lan2 lan3 support, wlan0 wlan1 - not
				devs=$(resolve_lower_devices "$i")
				for j in $devs; do
					# do not display error if addition failed
					nft_create_or_update_flowtable 'offload' "$j" 2>/dev/null
				done
			fi
		done
		;;
	esac
}

nft_only() {
	linux_fwtype

	case "$FWTYPE" in
	nftables)
		"$@"
		;;
	esac
}

nft_print_op() {
	echo "Adding nftables IPv$3 rule for $2: $1"
}
_nft_fw_tpws4() {
	# $1 - filter ipv4
	# $2 - tpws port
	# $3 - not-empty if WAN interface filtering required

	[ "$DISABLE_IPV4" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2"
		nft_print_op "$filter" "tpws (port $2)" 4
		nft_add_rule dnat_output skuid != "$WS_USER" ${3:+oifname @wanif }"$filter" ip daddr != @nozapret dnat ip to "$TPWS_LOCALHOST4":"$port"
		nft_add_rule dnat_pre iifname @lanif "$filter" ip daddr != @nozapret dnat ip to "$TPWS_LOCALHOST4":"$port"
		prepare_route_localnet
	}
}
_nft_fw_tpws6() {
	# $1 - filter ipv6
	# $2 - tpws port
	# $3 - LAN interface names space separated
	# $4 - not-empty if WAN interface filtering required

	[ "$DISABLE_IPV6" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" DNAT6 i
		nft_print_op "$filter" "tpws (port $port)" 6
		nft_add_rule dnat_output skuid != "$WS_USER" ${4:+oifname @wanif6 }"$filter" ip6 daddr != @nozapret6 dnat ip6 to [::1]:"$port"
		[ -n "$3" ] && {
			nft_add_rule dnat_pre "$filter" ip6 daddr != @nozapret6 dnat ip6 to iifname map @link_local:"$port"
			for i in $3; do
				_dnat6_target "$i" DNAT6
				# can be multiple tpws processes on different ports
				[ -n "$DNAT6" -a "$DNAT6" != '-' ] && nft_add_set_element link_local "$i : $DNAT6"
			done
		}
	}
}
nft_fw_tpws() {
	# $1 - filter ipv4
	# $2 - filter ipv6
	# $3 - tpws port

	nft_fw_tpws4 "$1" "$3"
	nft_fw_tpws6 "$2" "$3"
}
is_postnat() {
	[ "$POSTNAT" != 0 -o "$POSTNAT_ALL" = 1 ]
}
get_postchain() {
	if is_postnat; then
		echo -n postnat
	else
		echo -n postrouting
	fi
}
get_prechain() {
	if is_postnat; then
		echo -n prenat
	else
		echo -n prerouting
	fi
}
_nft_fw_nfqws_post4() {
	# $1 - filter ipv4
	# $2 - queue number
	# $3 - not-empty if WAN interface filtering required

	[ "$DISABLE_IPV4" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule chain=$(get_postchain) setmark
		nft_print_op "$filter" "nfqws postrouting (qnum $port)" 4
		rule="${3:+oifname @wanif }$filter ip daddr != @nozapret"
		is_postnat && setmark="meta mark set meta mark or $DESYNC_MARK_POSTNAT"
		nft_add_rule "$chain" "$rule" "$setmark" queue num "$port" bypass
		nft_add_nfqws_flow_exempt_rule "$rule"
	}
}
_nft_fw_nfqws_post6() {
	# $1 - filter ipv6
	# $2 - queue number
	# $3 - not-empty if WAN interface filtering required

	[ "$DISABLE_IPV6" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule chain=$(get_postchain) setmark
		nft_print_op "$filter" "nfqws postrouting (qnum $port)" 6
		rule="${3:+oifname @wanif6 }$filter ip6 daddr != @nozapret6"
		is_postnat && setmark="meta mark set meta mark or $DESYNC_MARK_POSTNAT"
		nft_add_rule "$chain" "$rule" "$setmark" queue num "$port" bypass
		nft_add_nfqws_flow_exempt_rule "$rule"
	}
}
nft_fw_nfqws_post() {
	# $1 - filter IPv4
	# $2 - filter ipv6
	# $3 - queue number

	nft_fw_nfqws_post4 "$1" "$3"
	nft_fw_nfqws_post6 "$2" "$3"
}

_nft_fw_nfqws_pre4() {
	# $1 - filter ipv4
	# $2 - queue number
	# $3 - not-empty if WAN interface filtering required

	[ "$DISABLE_IPV4" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule
		nft_print_op "$filter" "nfqws prerouting (qnum $port)" 4
		rule="${3:+iifname @wanif }$filter ip saddr != @nozapret"
		nft_add_rule $(get_prechain) "$rule" queue num "$port" bypass
	}
}
_nft_fw_nfqws_pre6() {
	# $1 - filter ipv6
	# $2 - queue number
	# $3 - not-empty if WAN interface filtering required

	[ "$DISABLE_IPV6" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule
		nft_print_op "$filter" "nfqws prerouting (qnum $port)" 6
		rule="${3:+iifname @wanif6 }$filter ip6 saddr != @nozapret6"
		nft_add_rule $(get_prechain) "$rule" queue num "$port" bypass
	}
}
nft_fw_nfqws_pre() {
	# $1 - filter ipv4
	# $2 - filter ipv6
	# $3 - queue number

	nft_fw_nfqws_pre4 "$1" "$3"
	nft_fw_nfqws_pre6 "$2" "$3"
}

nft_fw_nfqws_both4() {
	# $1 - filter ipv4
	# $2 - queue number
	nft_fw_nfqws_post4 "$@"
	nft_fw_nfqws_pre4 "$(nft_reverse_nfqws_rule "$1")" "$2"
}
nft_fw_nfqws_both6() {
	# $1 - filter ipv6
	# $2 - queue number
	nft_fw_nfqws_post6 "$@"
	nft_fw_nfqws_pre6 "$(nft_reverse_nfqws_rule "$1")" "$2"
}
nft_fw_nfqws_both() {
	# $1 - filter ipv4
	# $2 - filter ipv6
	# $3 - queue number
	nft_fw_nfqws_both4 "$1" "$3"
	nft_fw_nfqws_both6 "$2" "$3"
}

zapret_reload_ifsets() {
	nft_only nft_create_table
	nft_fill_ifsets_overload
	return 0
}
zapret_list_ifsets() {
	nft_only nft_list_ifsets
	return 0
}
zapret_list_table() {
	nft_only nft_list_table
	return 0
}

nft_produce_reverse_nfqws_rule() {
	local rule="$1"
	if contains "$rule" "$nft_connbytes "; then
		# autohostlist - need several incoming packets
		# autottl - need only one incoming packet
		[ "$MODE_FILTER" = autohostlist ] || rule=$(echo "$rule" | sed -re "s/$nft_connbytes [0-9]+-[0-9]+/$nft_connbytes 1/")
	else
		# old nft does not swallow 1-1
		local range=1
		[ "$MODE_FILTER" = autohostlist ] && range=$(first_packets_for_mode)
		[ "$range" = 1 ] || range="1-$range"
		rule="$nft_connbytes $range $rule"
	fi
	nft_reverse_nfqws_rule "$rule"
}
nft_fw_reverse_nfqws_rule4() {
	nft_fw_nfqws_pre4 "$(nft_produce_reverse_nfqws_rule "$1")" "$2"
}
nft_fw_reverse_nfqws_rule6() {
	nft_fw_nfqws_pre6 "$(nft_produce_reverse_nfqws_rule "$1")" "$2"
}
nft_fw_reverse_nfqws_rule() {
	# ensure that modes relying on incoming traffic work
	# $1 - rule4
	# $2 - rule6
	# $3 - queue number
	nft_fw_reverse_nfqws_rule4 "$1" "$3"
	nft_fw_reverse_nfqws_rule6 "$2" "$3"
}

zapret_apply_firewall_rules_nft() {
	local mode="${MODE_OVERRIDE:-$MODE}"

	local first_packets_only
	local desync="mark and $DESYNC_MARK == 0"
	local f4 f6 qn qns qn6 qns6

	first_packets_only="$nft_connbytes 1-$(first_packets_for_mode)"

	case "$mode" in
	tpws)
		if [ ! "$MODE_HTTP" = "1" ] && [ ! "$MODE_HTTPS" = "1" ]; then
			echo both HTTP and HTTPS are disabled. not applying redirection.
		else
			nft_filter_apply_port_target f4
			f6=$f4
			nft_filter_apply_ipset_target f4 f6
			nft_fw_tpws "$f4" "$f6" "$TPPORT"
		fi
		;;
	nfqws)
		local POSTNAT_SAVE=$POSTNAT

		POSTNAT=1
		# quite complex but we need to minimize nfqws processes to save RAM
		get_nfqws_qnums qn qns qn6 qns6
		if [ "$MODE_HTTP_KEEPALIVE" != "1" ] && [ -n "$qn" ] && [ "$qn" = "$qns" ]; then
			nft_filter_apply_port_target f4
			f4="$f4 $first_packets_only"
			nft_filter_apply_ipset_target4 f4
			nft_fw_nfqws_post4 "$f4 $desync" "$qn"
			nft_fw_reverse_nfqws_rule4 "$f4" "$qn"
		else
			if [ -n "$qn" ]; then
				f4="tcp dport {$HTTP_PORTS}"
				[ "$MODE_HTTP_KEEPALIVE" = "1" ] || f4="$f4 $first_packets_only"
				nft_filter_apply_ipset_target4 f4
				nft_fw_nfqws_post4 "$f4 $desync" "$qn"
				nft_fw_reverse_nfqws_rule4 "$f4" "$qn"
			fi
			if [ -n "$qns" ]; then
				f4="tcp dport {$HTTPS_PORTS} $first_packets_only"
				nft_filter_apply_ipset_target4 f4
				nft_fw_nfqws_post4 "$f4 $desync" "$qns"
				nft_fw_reverse_nfqws_rule4 "$f4" "$qns"
			fi
		fi
		if [ "$MODE_HTTP_KEEPALIVE" != "1" ] && [ -n "$qn6" ] && [ "$qn6" = "$qns6" ]; then
			nft_filter_apply_port_target f6
			f6="$f6 $first_packets_only"
			nft_filter_apply_ipset_target6 f6
			nft_fw_nfqws_post6 "$f6 $desync" "$qn6"
			nft_fw_reverse_nfqws_rule6 "$f6" "$qn6"
		else
			if [ -n "$qn6" ]; then
				f6="tcp dport {$HTTP_PORTS}"
				[ "$MODE_HTTP_KEEPALIVE" = "1" ] || f6="$f6 $first_packets_only"
				nft_filter_apply_ipset_target6 f6
				nft_fw_nfqws_post6 "$f6 $desync" "$qn6"
				nft_fw_reverse_nfqws_rule6 "$f6" "$qn6"
			fi
			if [ -n "$qns6" ]; then
				f6="tcp dport {$HTTPS_PORTS} $first_packets_only"
				nft_filter_apply_ipset_target6 f6
				nft_fw_nfqws_post6 "$f6 $desync" "$qns6"
				nft_fw_reverse_nfqws_rule6 "$f6" "$qns6"
			fi
		fi

		get_nfqws_qnums_quic qn qn6
		if [ -n "$qn" ]; then
			f4=
			nft_filter_apply_port_target_quic f4
			f4="$f4 $first_packets_only"
			nft_filter_apply_ipset_target4 f4
			nft_fw_nfqws_post4 "$f4 $desync" "$qn"
		fi
		if [ -n "$qn6" ]; then
			f6=
			nft_filter_apply_port_target_quic f6
			f6="$f6 $first_packets_only"
			nft_filter_apply_ipset_target6 f6
			nft_fw_nfqws_post6 "$f6 $desync" "$qn6"
		fi

		POSTNAT=$POSTNAT_SAVE
		;;
	custom)
		existf zapret_custom_firewall_nft && zapret_custom_firewall_nft
		;;
	esac
}

zapret_apply_firewall_nft() {
	echo Applying nftables

	local mode="${MODE_OVERRIDE:-$MODE}"

	[ "$mode" = "tpws-socks" ] && return 0

	create_ipset no-update
	nft_create_firewall
	nft_fill_ifsets_overload

	zapret_apply_firewall_rules_nft

	[ "$FLOWOFFLOAD" = 'software' -o "$FLOWOFFLOAD" = 'hardware' ] && nft_apply_flow_offloading

	return 0
}
zapret_unapply_firewall_nft() {
	echo Clearing nftables

	unprepare_route_localnet
	nft_del_firewall
	return 0
}
zapret_do_firewall_nft() {
	# $1 - 1 - add, 0 - del

	if [ "$1" = 0 ]; then
		zapret_unapply_firewall_nft
	else
		zapret_apply_firewall_nft
	fi

	return 0
}
