[ -n "$ZAPRET_NFT_TABLE" ] || ZAPRET_NFT_TABLE=zapret
nft_connbytes="ct original packets"

# required for : nft -f -
create_dev_stdin
std_ports

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
nft_flush_chain()
{
	# $1 - chain name
	nft flush chain inet $ZAPRET_NFT_TABLE $1
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
	add rule inet  $ZAPRET_NFT_TABLE input iif != lo jump localnet_protect
	add chain inet $ZAPRET_NFT_TABLE postrouting
	flush chain inet $ZAPRET_NFT_TABLE postrouting
	add chain inet $ZAPRET_NFT_TABLE postrouting_hook { type filter hook postrouting priority 99; }
	flush chain inet $ZAPRET_NFT_TABLE postrouting_hook
	add rule inet  $ZAPRET_NFT_TABLE postrouting_hook mark and $DESYNC_MARK == 0 jump postrouting
	add chain inet $ZAPRET_NFT_TABLE postnat
	flush chain inet $ZAPRET_NFT_TABLE postnat
	add chain inet $ZAPRET_NFT_TABLE postnat_hook { type filter hook postrouting priority 101; }
	flush chain inet $ZAPRET_NFT_TABLE postnat_hook
	add rule inet  $ZAPRET_NFT_TABLE postnat_hook mark and $DESYNC_MARK == 0 jump postnat
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
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws ip frag-off & 0x1fff != 0 notrack comment "ipfrag"
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws exthdr frag exists notrack comment "ipfrag"
	add rule inet $ZAPRET_NFT_TABLE predefrag_nfqws tcp flags ! syn,rst,ack notrack comment "datanoack"
	add set inet $ZAPRET_NFT_TABLE lanif { type ifname; }
	add set inet $ZAPRET_NFT_TABLE wanif { type ifname; }
	add set inet $ZAPRET_NFT_TABLE wanif6 { type ifname; }
	add map inet $ZAPRET_NFT_TABLE link_local { type ifname : ipv6_addr; }

EOF
	[ -n "$POSTNAT_ALL" ] && {
		nft_flush_chain predefrag_nfqws
		nft_add_rule predefrag_nfqws notrack comment \"do not track nfqws generated packets to avoid nat tampering and defragmentation\"
	}
	[ "$FILTER_TTL_EXPIRED_ICMP" = 1 ] && {
		if is_postnat; then
			# can be caused by untracked nfqws-generated packets
			nft_add_rule prerouting icmp type time-exceeded ct state invalid drop
		else
			nft_add_rule postrouting_hook mark and $DESYNC_MARK != 0 ct mark set ct mark or $DESYNC_MARK comment \"nfqws related : prevent ttl expired socket errors\"
		fi
		[ "$DISABLE_IPV4" = "1" ] || {
			nft_add_rule prerouting icmp type time-exceeded ct mark and $DESYNC_MARK != 0 drop comment \"nfqws related : prevent ttl expired socket errors\"
		}
		[ "$DISABLE_IPV6" = "1" ] || {
			nft_add_rule prerouting icmpv6 type time-exceeded ct mark and $DESYNC_MARK != 0 drop comment \"nfqws related : prevent ttl expired socket errors\"
		}
	}
}
nft_del_chains()
{
	# do not delete all chains because of additional user hooks
	# they must be inside zapret table to use nfsets

	# these chains are newer. do not fail all because chains are not present
cat << EOF | nft -f - 2>/dev/null
	delete chain inet $ZAPRET_NFT_TABLE postrouting_hook
	delete chain inet $ZAPRET_NFT_TABLE postnat_hook
EOF

cat << EOF | nft -f - 2>/dev/null
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
nft_del_flowtable()
{
	nft delete flowtable inet $ZAPRET_NFT_TABLE ft 2>/dev/null
}
nft_create_or_update_flowtable()
{
	# $1 = flags ('offload' for hw offload)
	# $2,$3,$4,... - interfaces
	# can be called multiple times to add interfaces. interfaces can only be added , not removed
	local flags=$1 devices makelist
	shift
	# warning ! nft versions at least up to 1.0.1 do not allow interface names starting with digit in flowtable and do not allow quoting
	# warning ! openwrt fixes this in post-21.x snapshots with special nft patch
	# warning ! in traditional linux distros nft is unpatched and will fail with quoted interface definitions if unfixed
	[ -n "$flags" ] && flags="flags $flags;"
	for makelist in make_quoted_comma_list make_comma_list; do
		$makelist devices "$@"
		[ -n "$devices" ] && devices="devices={$devices};"
		nft add flowtable inet $ZAPRET_NFT_TABLE ft "{ hook ingress priority -1; $flags $devices }" && break
	done
}
nft_flush_ifsets()
{
cat << EOF | nft -f -  2>/dev/null
	flush set inet $ZAPRET_NFT_TABLE lanif
	flush set inet $ZAPRET_NFT_TABLE wanif
	flush set inet $ZAPRET_NFT_TABLE wanif6
	flush map inet $ZAPRET_NFT_TABLE link_local
EOF
}
nft_flush_link_local()
{
	nft flush map inet $ZAPRET_NFT_TABLE link_local 2>/dev/null
}
nft_list_ifsets()
{
	nft list set inet $ZAPRET_NFT_TABLE lanif
	nft list set inet $ZAPRET_NFT_TABLE wanif
	nft list set inet $ZAPRET_NFT_TABLE wanif6
	nft list map inet $ZAPRET_NFT_TABLE link_local
	nft list flowtable inet $ZAPRET_NFT_TABLE ft 2>/dev/null
}

nft_create_firewall()
{
	nft_create_table
	nft_del_flowtable
	nft_flush_link_local
	nft_create_chains
}
nft_del_firewall()
{
	nft_del_chains
	nft_del_flowtable
	nft_flush_link_local
	# leave ifsets and ipsets because they may be used by custom rules
}

nft_add_rule()
{
	# $1 - chain
	# $2,$3,... - rule(s)
	local chain="$1"
	shift
	nft add rule inet $ZAPRET_NFT_TABLE $chain $FW_EXTRA_PRE "$@"
}
nft_insert_rule()
{
	# $1 - chain
	# $2,$3,... - rule(s)
	local chain="$1"
	shift
	nft insert rule inet $ZAPRET_NFT_TABLE $chain $FW_EXTRA_PRE "$@"
}
nft_add_set_element()
{
	# $1 - set or map name
	# $2 - element
	[ -z "$2" ] || nft add element inet $ZAPRET_NFT_TABLE $1 "{ $2 }"
}
nft_add_set_elements()
{
	# $1 - set or map name
	# $2,$3,... - element(s)
	local set="$1" elements
	shift
	make_comma_list elements "$@"
	nft_add_set_element $set "$elements"
}
nft_reverse_nfqws_rule()
{
	echo "$@" | sed -e 's/oifname /iifname /g' -e 's/dport /sport /g' -e 's/daddr /saddr /g' -e 's/ct original /ct reply /g' -e "s/mark and $DESYNC_MARK == 0//g"
}
nft_clean_nfqws_rule()
{
	echo "$@" | sed -e "s/mark and $DESYNC_MARK == 0//g" -e "s/oifname @wanif6//g" -e "s/oifname @wanif//g"
}
nft_add_nfqws_flow_exempt_rule()
{
	# $1 - rule (must be all filters in one var)
	local FW_EXTRA_POST= FW_EXTRA_PRE=
	nft_add_rule flow_offload $(nft_clean_nfqws_rule $1) return comment \"direct flow offloading exemption\"
	# do not need this because of oifname @wanif/@wanif6 filter in forward chain
	#nft_add_rule flow_offload $(nft_reverse_nfqws_rule $1) return comment \"reverse flow offloading exemption\"
}
nft_add_flow_offload_exemption()
{
	# "$1" - rule for ipv4
	# "$2" - rule for ipv6
	# "$3" - comment
	local FW_EXTRA_POST= FW_EXTRA_PRE=
	[ "$DISABLE_IPV4" = "1" -o -z "$1" ] || nft_add_rule flow_offload oifname @wanif $1 ip daddr != @nozapret return comment \"$3\"
	[ "$DISABLE_IPV6" = "1" -o -z "$2" ] || nft_add_rule flow_offload oifname @wanif6 $2 ip6 daddr != @nozapret6 return comment \"$3\"
}

nft_apply_flow_offloading()
{
	# ft can be absent
	nft_add_rule flow_offload meta l4proto "{ tcp, udp }" flow add @ft 2>/dev/null && {
		nft_add_rule flow_offload meta l4proto "{ tcp, udp }" counter comment \"if offload works here must not be too much traffic\"
		# allow only outgoing packets to initiate flow offload
		nft_add_rule forward oifname @wanif jump flow_offload
		nft_add_rule forward oifname @wanif6 jump flow_offload
	}
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


nft_script_add_ifset_element()
{
	# $1 - set name
	# $2 - space separated elements
	local elements
	[ -n "$2" ] && {
		make_quoted_comma_list elements $2
		script="${script}
add element inet $ZAPRET_NFT_TABLE $1 { $elements }"
	}
}
nft_fill_ifsets()
{
	# $1 - space separated lan interface names
	# $2 - space separated wan interface names
	# $3 - space separated wan6 interface names
	# 4,5,6 is needed for pppoe+openwrt case. looks like it's not easily possible to resolve ethernet device behind a pppoe interface
	# $4 - space separated lan physical interface names (optional)
	# $5 - space separated wan physical interface names (optional)
	# $6 - space separated wan6 physical interface names (optional)

	local script i j ALLDEVS devs b

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
			ALLDEVS=$(unique $1 $2 $3)
			# unbound flowtable may cause error in older nft version
			nft_create_or_update_flowtable '' $ALLDEVS 2>/dev/null
			;;
		hardware)
			ALLDEVS=$(unique $1 $2 $3 $4 $5 $6)
			# first create unbound flowtable. may cause error in older nft version
			nft_create_or_update_flowtable 'offload' 2>/dev/null
			# then add elements. some of them can cause error because unsupported
			for i in $ALLDEVS; do
				# bridge members must be added instead of the bridge itself
				# some members may not support hw offload. example : lan1 lan2 lan3 support, wlan0 wlan1 - not
				b=
				devs=$(resolve_lower_devices $i)
				for j in $devs; do
					# do not display error if addition failed
					nft_create_or_update_flowtable 'offload' $j && b=1 2>/dev/null
				done
				[ -n "$b" ] || {
					# no lower devices added ? try to add interface itself
					nft_create_or_update_flowtable 'offload' $i 2>/dev/null
				}
			done
			;;
	esac
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


nft_print_op()
{
	echo "Inserting nftables ipv$3 rule for $2 : $1"
}
_nft_fw_tpws4()
{
	# $1 - filter ipv4
	# $2 - tpws port
	# $3 - not-empty if wan interface filtering required

	[ "$DISABLE_IPV4" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2"
		nft_print_op "$filter" "tpws (port $2)" 4
		nft_insert_rule dnat_output skuid != $WS_USER ${3:+oifname @wanif }$filter ip daddr != @nozapret ip daddr != @ipban $FW_EXTRA_POST dnat ip to $TPWS_LOCALHOST4:$port
		nft_insert_rule dnat_pre iifname @lanif $filter ip daddr != @nozapret ip daddr != @ipban $FW_EXTRA_POST dnat ip to $TPWS_LOCALHOST4:$port
		prepare_route_localnet
	}
}
_nft_fw_tpws6()
{
	# $1 - filter ipv6
	# $2 - tpws port
	# $3 - lan interface names space separated
	# $4 - not-empty if wan interface filtering required

	[ "$DISABLE_IPV6" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" DNAT6 i
		nft_print_op "$filter" "tpws (port $port)" 6
		nft_insert_rule dnat_output skuid != $WS_USER ${4:+oifname @wanif6 }$filter ip6 daddr != @nozapret6 ip6 daddr != @ipban6 $FW_EXTRA_POST dnat ip6 to [::1]:$port
		[ -n "$3" ] && {
			nft_insert_rule dnat_pre $filter ip6 daddr != @nozapret6 ip6 daddr != @ipban6 $FW_EXTRA_POST dnat ip6 to iifname map @link_local:$port
			for i in $3; do
				_dnat6_target $i DNAT6
				# can be multiple tpws processes on different ports
				[ -n "$DNAT6" -a "$DNAT6" != '-' ] && nft_add_set_element link_local "$i : $DNAT6"
			done
		}
	}
}
nft_fw_tpws()
{
	# $1 - filter ipv4
	# $2 - filter ipv6
	# $3 - tpws port

	nft_fw_tpws4 "$1" $3
	nft_fw_tpws6 "$2" $3
}
is_postnat()
{
	[ "$POSTNAT" != 0 -o "$POSTNAT_ALL" = 1 ]
}
get_postchain()
{
	if is_postnat ; then
		echo -n postnat
	else
		echo -n postrouting
	fi
}
get_prechain()
{
	if is_postnat ; then
		echo -n prenat
	else
		echo -n prerouting
	fi
}
_nft_fw_nfqws_post4()
{
	# $1 - filter ipv4
	# $2 - queue number
	# $3 - not-empty if wan interface filtering required

	[ "$DISABLE_IPV4" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule chain=$(get_postchain) setmark
		nft_print_op "$filter" "nfqws postrouting (qnum $port)" 4
		rule="${3:+oifname @wanif }$filter ip daddr != @nozapret"
		is_postnat && setmark="meta mark set meta mark or $DESYNC_MARK_POSTNAT"
		nft_insert_rule $chain $rule $setmark $CONNMARKER $FW_EXTRA_POST queue num $port bypass
		nft_add_nfqws_flow_exempt_rule "$rule"
	}
}
_nft_fw_nfqws_post6()
{
	# $1 - filter ipv6
	# $2 - queue number
	# $3 - not-empty if wan interface filtering required

	[ "$DISABLE_IPV6" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule chain=$(get_postchain) setmark
		nft_print_op "$filter" "nfqws postrouting (qnum $port)" 6
		rule="${3:+oifname @wanif6 }$filter ip6 daddr != @nozapret6"
		is_postnat && setmark="meta mark set meta mark or $DESYNC_MARK_POSTNAT"
		nft_insert_rule $chain $rule $setmark $CONNMARKER $FW_EXTRA_POST queue num $port bypass
		nft_add_nfqws_flow_exempt_rule "$rule"
	}
}
nft_fw_nfqws_post()
{
	# $1 - filter ipv4
	# $2 - filter ipv6
	# $3 - queue number

	nft_fw_nfqws_post4 "$1" $3
	nft_fw_nfqws_post6 "$2" $3
}

_nft_fw_nfqws_pre4()
{
	# $1 - filter ipv4
	# $2 - queue number
	# $3 - not-empty if wan interface filtering required

	[ "$DISABLE_IPV4" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule
		nft_print_op "$filter" "nfqws prerouting (qnum $port)" 4
		rule="${3:+iifname @wanif }$filter ip saddr != @nozapret"
		nft_insert_rule $(get_prechain) $rule $CONNMARKER $FW_EXTRA_POST queue num $port bypass
	}
}
_nft_fw_nfqws_pre6()
{
	# $1 - filter ipv6
	# $2 - queue number
	# $3 - not-empty if wan interface filtering required

	[ "$DISABLE_IPV6" = "1" -o -z "$1" ] || {
		local filter="$1" port="$2" rule
		nft_print_op "$filter" "nfqws prerouting (qnum $port)" 6
		rule="${3:+iifname @wanif6 }$filter ip6 saddr != @nozapret6"
		nft_insert_rule $(get_prechain) $rule $CONNMARKER $FW_EXTRA_POST queue num $port bypass
	}
}
nft_fw_nfqws_pre()
{
	# $1 - filter ipv4
	# $2 - filter ipv6
	# $3 - queue number

	nft_fw_nfqws_pre4 "$1" $3
	nft_fw_nfqws_pre6 "$2" $3
}

nft_fw_nfqws_both4()
{
	# $1 - filter ipv4
	# $2 - queue number
	nft_fw_nfqws_post4 "$@"
	nft_fw_nfqws_pre4 "$(nft_reverse_nfqws_rule $1)" $2
}
nft_fw_nfqws_both6()
{
	# $1 - filter ipv6
	# $2 - queue number
	nft_fw_nfqws_post6 "$@"
	nft_fw_nfqws_pre6 "$(nft_reverse_nfqws_rule $1)" $2
}
nft_fw_nfqws_both()
{
	# $1 - filter ipv4
	# $2 - filter ipv6
	# $3 - queue number
	nft_fw_nfqws_both4 "$1" "$3"
	nft_fw_nfqws_both6 "$2" "$3"
}

zapret_reload_ifsets()
{
	nft_only nft_create_table ; nft_fill_ifsets_overload
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



nft_fw_reverse_nfqws_rule4()
{
	nft_fw_nfqws_pre4 "$(nft_reverse_nfqws_rule "$1")" $2
}
nft_fw_reverse_nfqws_rule6()
{
	nft_fw_nfqws_pre6 "$(nft_reverse_nfqws_rule "$1")" $2
}
nft_fw_reverse_nfqws_rule()
{
	# ensure that modes relying on incoming traffic work
	# $1 - rule4
	# $2 - rule6
	# $3 - queue number
	nft_fw_reverse_nfqws_rule4 "$1" $3
	nft_fw_reverse_nfqws_rule6 "$2" $3
}

nft_first_packets()
{
	# $1 - packet count
	[ -n "$1" -a "$1" != keepalive ] && [ "$1" -ge 1 ] &&
	{
		if [ "$1" = 1 ] ; then
			echo "$nft_connbytes 1"
		else
			echo "$nft_connbytes 1-$1"
		fi
	}
}

nft_apply_nfqws_in_out()
{
	# $1 - tcp,udp
	# $2 - ports
	# $3 - PKT_OUT. special value : 'keepalive'
	# $4 - PKT_IN
	local f4 f6 first_packets_only
	[ -n "$2" ] || return
	[ -n "$3" -a "$3" != 0 ] &&
	{
		first_packets_only="$(nft_first_packets $3)"
		f4="$1 dport {$2} $first_packets_only"
		f6=$f4
		nft_filter_apply_ipset_target f4 f6
		nft_fw_nfqws_post "$f4" "$f6" $QNUM
	}
	[ -n "$4" -a "$4" != 0 ] &&
	{
		first_packets_only="$(nft_first_packets $4)"
		f4="$1 dport {$2} $first_packets_only"
		f6=$f4
		nft_filter_apply_ipset_target f4 f6
		nft_fw_reverse_nfqws_rule "$f4" "$f6" $QNUM
	}
}

zapret_apply_firewall_standard_tpws_rules_nft()
{
	local f4 f6

	[ "$TPWS_ENABLE" = 1 -a -n "$TPWS_PORTS" ] && {
		f4="tcp dport {$TPWS_PORTS}"
		f6=$f4
		nft_filter_apply_ipset_target f4 f6
		nft_fw_tpws "$f4" "$f6" $TPPORT
	}
}
zapret_apply_firewall_standard_nfqws_rules_nft()
{
	[ "$NFQWS_ENABLE" = 1 ] && {
		nft_apply_nfqws_in_out tcp "$NFQWS_PORTS_TCP" "$NFQWS_TCP_PKT_OUT" "$NFQWS_TCP_PKT_IN"
		nft_apply_nfqws_in_out tcp "$NFQWS_PORTS_TCP_KEEPALIVE" keepalive "$NFQWS_TCP_PKT_IN"
		nft_apply_nfqws_in_out udp "$NFQWS_PORTS_UDP" "$NFQWS_UDP_PKT_OUT" "$NFQWS_UDP_PKT_IN"
		nft_apply_nfqws_in_out udp "$NFQWS_PORTS_UDP_KEEPALIVE" keepalive "$NFQWS_UDP_PKT_IN"
	}
}
zapret_apply_firewall_standard_rules_nft()
{
	zapret_apply_firewall_standard_tpws_rules_nft
	zapret_apply_firewall_standard_nfqws_rules_nft
}

zapret_apply_firewall_rules_nft()
{
	zapret_apply_firewall_standard_rules_nft
	custom_runner zapret_custom_firewall_nft
}

zapret_apply_firewall_nft()
{
	echo Applying nftables

	create_ipset no-update
	nft_create_firewall
	nft_fill_ifsets_overload

	zapret_apply_firewall_rules_nft

	[ "$FLOWOFFLOAD" = 'software' -o "$FLOWOFFLOAD" = 'hardware' ] && nft_apply_flow_offloading

	return 0
}
zapret_unapply_firewall_nft()
{
	echo Clearing nftables

	unprepare_route_localnet
	nft_del_firewall
	custom_runner zapret_custom_firewall_nft_flush
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

# ctmark is not available in POSTNAT mode
CONNMARKER=
[ "$FILTER_TTL_EXPIRED_ICMP" = 1 ] && is_postnat && CONNMARKER="ct mark set ct mark or $DESYNC_MARK"
