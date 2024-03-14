std_ports
readonly ipt_connbytes="-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes"

ipt()
{
	iptables -C "$@" >/dev/null 2>/dev/null || iptables -I "$@"
}
ipta()
{
	iptables -C "$@" >/dev/null 2>/dev/null || iptables -A "$@"
}
ipt_del()
{
	iptables -C "$@" >/dev/null 2>/dev/null && iptables -D "$@"
}
ipt_add_del()
{
	on_off_function ipt ipt_del "$@"
}
ipta_add_del()
{
	on_off_function ipta ipt_del "$@"
}
ipt6()
{
	ip6tables -C "$@" >/dev/null 2>/dev/null || ip6tables -I "$@"
}
ipt6a()
{
	ip6tables -C "$@" >/dev/null 2>/dev/null || ip6tables -A "$@"
}
ipt6_del()
{
	ip6tables -C "$@" >/dev/null 2>/dev/null && ip6tables -D "$@"
}
ipt6_add_del()
{
	on_off_function ipt6 ipt6_del "$@"
}
ipt6a_add_del()
{
	on_off_function ipt6 ipt6a_del "$@"
}

is_ipt_flow_offload_avail()
{
	# $1 = '' for ipv4, '6' for ipv6
	grep -q FLOWOFFLOAD 2>/dev/null /proc/net/ip$1_tables_targets
}

filter_apply_port_target()
{
	# $1 - var name of iptables filter
	local f
	if [ "$MODE_HTTP" = "1" ] && [ "$MODE_HTTPS" = "1" ]; then
		f="-p tcp -m multiport --dports $HTTP_PORTS_IPT,$HTTPS_PORTS_IPT"
	elif [ "$MODE_HTTPS" = "1" ]; then
		f="-p tcp -m multiport --dports $HTTPS_PORTS_IPT"
	elif [ "$MODE_HTTP" = "1" ]; then
		f="-p tcp -m multiport --dports $HTTP_PORTS_IPT"
	else
		echo WARNING !!! HTTP and HTTPS are both disabled
	fi
	eval $1="\"\$$1 $f\""
}
filter_apply_port_target_quic()
{
	# $1 - var name of nftables filter
	local f
	f="-p udp -m multiport --dports $QUIC_PORTS_IPT"
	eval $1="\"\$$1 $f\""
}
filter_apply_ipset_target4()
{
	# $1 - var name of ipv4 iptables filter
	if [ "$MODE_FILTER" = "ipset" ]; then
		eval $1="\"\$$1 -m set --match-set zapret dst\""
	fi
}
filter_apply_ipset_target6()
{
	# $1 - var name of ipv6 iptables filter
	if [ "$MODE_FILTER" = "ipset" ]; then
		eval $1="\"\$$1 -m set --match-set zapret6 dst\""
	fi
}
filter_apply_ipset_target()
{
	# $1 - var name of ipv4 iptables filter
	# $2 - var name of ipv6 iptables filter
	filter_apply_ipset_target4 $1
	filter_apply_ipset_target6 $2
}

reverse_nfqws_rule_stream()
{
	sed -e 's/-o /-i /g' -e 's/--dport /--sport /g' -e 's/--dports /--sports /g' -e 's/ dst$/ src/' -e 's/ dst / src /g' -e 's/--connbytes-dir=original/--connbytes-dir=reply/g' -e "s/-m mark ! --mark $DESYNC_MARK\/$DESYNC_MARK//g"
}
reverse_nfqws_rule()
{
	echo "$@" | reverse_nfqws_rule_stream
}

prepare_tpws_fw4()
{
	# otherwise linux kernel will treat 127.0.0.0/8 as "martian" ip and refuse routing to it
	# NOTE : kernels <3.6 do not have this feature. consider upgrading or change DNAT to REDIRECT and do not bind to 127.0.0.0/8

	[ "$DISABLE_IPV4" = "1" ] || {
		iptables -N input_rule_zapret 2>/dev/null
		ipt input_rule_zapret -d $TPWS_LOCALHOST4 -j RETURN
		ipta input_rule_zapret -d 127.0.0.0/8 -j DROP
		ipt INPUT ! -i lo -j input_rule_zapret

		prepare_route_localnet
	}
}
unprepare_tpws_fw4()
{
	[ "$DISABLE_IPV4" = "1" ] || {
		unprepare_route_localnet

		ipt_del INPUT ! -i lo -j input_rule_zapret
		iptables -F input_rule_zapret 2>/dev/null
		iptables -X input_rule_zapret 2>/dev/null
	}
}
unprepare_tpws_fw()
{
	unprepare_tpws_fw4
}


ipt_print_op()
{
	if [ "$1" = "1" ]; then
		echo "Adding ip$4tables rule for $3 : $2"
	else
		echo "Deleting ip$4tables rule for $3 : $2"
	fi
}

_fw_tpws4()
{
	# $1 - 1 - add, 0 - del
	# $2 - iptable filter for ipv4
	# $3 - tpws port
	# $4 - lan interface names space separated
	# $5 - wan interface names space separated
	[ "$DISABLE_IPV4" = "1" -o -z "$2" ] || {
		local i rule

		[ "$1" = 1 ] && prepare_tpws_fw4

		ipt_print_op $1 "$2" "tpws (port $3)"

		rule="$2 $IPSET_EXCLUDE dst -j DNAT --to $TPWS_LOCALHOST4:$3"
		for i in $4 ; do
			ipt_add_del $1 PREROUTING -t nat -i $i $rule
	 	done

		rule="-m owner ! --uid-owner $WS_USER $rule"
		if [ -n "$5" ]; then
			for i in $5; do
				ipt_add_del $1 OUTPUT -t nat -o $i $rule
			done
		else
			ipt_add_del $1 OUTPUT -t nat $rule
		fi
	}
}
_fw_tpws6()
{
	# $1 - 1 - add, 0 - del
	# $2 - iptable filter for ipv6
	# $3 - tpws port
	# $4 - lan interface names space separated
	# $5 - wan interface names space separated

	[ "$DISABLE_IPV6" = "1" -o -z "$2" ] || {
		local i rule DNAT6

		ipt_print_op $1 "$2" "tpws (port $3)" 6

		rule="$2 $IPSET_EXCLUDE6 dst"
		for i in $4 ; do
			_dnat6_target $i DNAT6
			[ -n "$DNAT6" -a "$DNAT6" != "-" ] && ipt6_add_del $1 PREROUTING -t nat -i $i $rule -j DNAT --to [$DNAT6]:$3
	 	done

		rule="-m owner ! --uid-owner $WS_USER $rule -j DNAT --to [::1]:$3"
		if [ -n "$5" ]; then
			for i in $5; do
				ipt6_add_del $1 OUTPUT -t nat -o $i $rule
			done
		else
			ipt6_add_del $1 OUTPUT -t nat $rule
		fi
	}
}
fw_tpws()
{
	# $1 - 1 - add, 0 - del
	# $2 - iptable filter for ipv4
	# $3 - iptable filter for ipv6
	# $4 - tpws port
	fw_tpws4 $1 "$2" $4
	fw_tpws6 $1 "$3" $4
}


_fw_nfqws_post4()
{
	# $1 - 1 - add, 0 - del
	# $2 - iptable filter for ipv4
	# $3 - queue number
	# $4 - wan interface names space separated
	[ "$DISABLE_IPV4" = "1" -o -z "$2" ] || {
		local i

		ipt_print_op $1 "$2" "nfqws postrouting (qnum $3)"

		rule="$2 $IPSET_EXCLUDE dst -j NFQUEUE --queue-num $3 --queue-bypass"
		if [ -n "$4" ] ; then
			for i in $4; do
				ipt_add_del $1 POSTROUTING -t mangle -o $i $rule
			done
		else
			ipt_add_del $1 POSTROUTING -t mangle $rule
		fi
	}
}
_fw_nfqws_post6()
{
	# $1 - 1 - add, 0 - del
	# $2 - iptable filter for ipv6
	# $3 - queue number
	# $4 - wan interface names space separated
	[ "$DISABLE_IPV6" = "1" -o -z "$2" ] || {
		local i

		ipt_print_op $1 "$2" "nfqws postrouting (qnum $3)" 6

		rule="$2 $IPSET_EXCLUDE6 dst -j NFQUEUE --queue-num $3 --queue-bypass"
		if [ -n "$4" ] ; then
			for i in $4; do
				ipt6_add_del $1 POSTROUTING -t mangle -o $i $rule
			done
		else
			ipt6_add_del $1 POSTROUTING -t mangle $rule
		fi
	}
}
fw_nfqws_post()
{
	# $1 - 1 - add, 0 - del
	# $2 - iptable filter for ipv4
	# $3 - iptable filter for ipv6
	# $4 - queue number
	fw_nfqws_post4 $1 "$2" $4
	fw_nfqws_post6 $1 "$3" $4
}

_fw_nfqws_pre4()
{
	# $1 - 1 - add, 0 - del
	# $2 - iptable filter for ipv4
	# $3 - queue number
	# $4 - wan interface names space separated
	[ "$DISABLE_IPV4" = "1" -o -z "$2" ] || {
		local i

		ipt_print_op $1 "$2" "nfqws input+forward (qnum $3)"

		rule="$2 $IPSET_EXCLUDE src -j NFQUEUE --queue-num $3 --queue-bypass"
		if [ -n "$4" ] ; then
			for i in $4; do
				# iptables PREROUTING chain is before NAT. not possible to have DNATed ip's there
				ipt_add_del $1 INPUT -t mangle -i $i $rule
				ipt_add_del $1 FORWARD -t mangle -i $i $rule
			done
		else
			ipt_add_del $1 INPUT -t mangle $rule
			ipt_add_del $1 FORWARD -t mangle $rule
		fi
	}
}
_fw_nfqws_pre6()
{
	# $1 - 1 - add, 0 - del
	# $2 - iptable filter for ipv6
	# $3 - queue number
	# $4 - wan interface names space separated
	[ "$DISABLE_IPV6" = "1" -o -z "$2" ] || {
		local i

		ipt_print_op $1 "$2" "nfqws input+forward (qnum $3)" 6

		rule="$2 $IPSET_EXCLUDE6 src -j NFQUEUE --queue-num $3 --queue-bypass"
		if [ -n "$4" ] ; then
			for i in $4; do
				# iptables PREROUTING chain is before NAT. not possible to have DNATed ip's there
				ipt6_add_del $1 INPUT -t mangle -i $i $rule
				ipt6_add_del $1 FORWARD -t mangle -i $i $rule
			done
		else
			ipt6_add_del $1 INPUT -t mangle $rule
			ipt6_add_del $1 FORWARD -t mangle $rule
		fi
	}
}
fw_nfqws_pre()
{
	# $1 - 1 - add, 0 - del
	# $2 - iptable filter for ipv4
	# $3 - iptable filter for ipv6
	# $4 - queue number
	fw_nfqws_pre4 $1 "$2" $4
	fw_nfqws_pre6 $1 "$3" $4
}


produce_reverse_nfqws_rule()
{
	local rule="$1"
	if contains "$rule" "$ipt_connbytes"; then
		# autohostlist - need several incoming packets
		# autottl - need only one incoming packet
		[ "$MODE_FILTER" = autohostlist ] || rule=$(echo "$rule" | sed -re "s/$ipt_connbytes [0-9]+:[0-9]+/$ipt_connbytes 1:1/")
	else
		local n=1
		[ "$MODE_FILTER" = autohostlist ] && n=$(first_packets_for_mode)
		rule="$ipt_connbytes 1:$n $rule"
	fi
	echo "$rule" | reverse_nfqws_rule_stream
}
fw_reverse_nfqws_rule4()
{
	fw_nfqws_pre4 $1 "$(produce_reverse_nfqws_rule "$2")" $3
}
fw_reverse_nfqws_rule6()
{
	fw_nfqws_pre6 $1 "$(produce_reverse_nfqws_rule "$2")" $3
}
fw_reverse_nfqws_rule()
{
	# ensure that modes relying on incoming traffic work
	# $1 - 1 - add, 0 - del
	# $2 - rule4
	# $3 - rule6
	# $4 - queue number
	fw_reverse_nfqws_rule4 $1 "$2" $4
	fw_reverse_nfqws_rule6 $1 "$3" $4
}


zapret_do_firewall_rules_ipt()
{
	local mode="${MODE_OVERRIDE:-$MODE}"

	local first_packet_only="$ipt_connbytes 1:$(first_packets_for_mode)"
	local desync="-m mark ! --mark $DESYNC_MARK/$DESYNC_MARK"
	local n f4 f6 qn qns qn6 qns6

	case "$mode" in
		tpws)
			if [ ! "$MODE_HTTP" = "1" ] && [ ! "$MODE_HTTPS" = "1" ]; then
				echo both http and https are disabled. not applying redirection.
			else
				filter_apply_port_target f4
				f6=$f4
				filter_apply_ipset_target f4 f6
				fw_tpws $1 "$f4" "$f6" $TPPORT
			fi
			;;
	
		nfqws)
			# quite complex but we need to minimize nfqws processes to save RAM
			get_nfqws_qnums qn qns qn6 qns6
			if [ "$MODE_HTTP_KEEPALIVE" != "1" ] && [ -n "$qn" ] && [ "$qn" = "$qns" ]; then
				filter_apply_port_target f4
				f4="$f4 $first_packet_only"
				filter_apply_ipset_target4 f4
				fw_nfqws_post4 $1 "$f4 $desync" $qn
				fw_reverse_nfqws_rule4 $1 "$f4" $qn
			else
				if [ -n "$qn" ]; then
					f4="-p tcp -m multiport --dports $HTTP_PORTS_IPT"
					[ "$MODE_HTTP_KEEPALIVE" = "1" ] || f4="$f4 $first_packet_only"
					filter_apply_ipset_target4 f4
					fw_nfqws_post4 $1 "$f4 $desync" $qn
					fw_reverse_nfqws_rule4 $1 "$f4" $qn
				fi
				if [ -n "$qns" ]; then
					f4="-p tcp -m multiport --dports $HTTPS_PORTS_IPT $first_packet_only"
					filter_apply_ipset_target4 f4
					fw_nfqws_post4 $1 "$f4 $desync" $qns
					fw_reverse_nfqws_rule4 $1 "$f4" $qns
				fi
			fi
			if [ "$MODE_HTTP_KEEPALIVE" != "1" ] && [ -n "$qn6" ] && [ "$qn6" = "$qns6" ]; then
				filter_apply_port_target f6
				f6="$f6 $first_packet_only"
				filter_apply_ipset_target6 f6
				fw_nfqws_post6 $1 "$f6 $desync" $qn6
				fw_reverse_nfqws_rule6 $1 "$f6" $qn6
			else
				if [ -n "$qn6" ]; then
					f6="-p tcp -m multiport --dports $HTTP_PORTS_IPT"
					[ "$MODE_HTTP_KEEPALIVE" = "1" ] || f6="$f6 $first_packet_only"
					filter_apply_ipset_target6 f6
					fw_nfqws_post6 $1 "$f6 $desync" $qn6
					fw_reverse_nfqws_rule6 $1 "$f6" $qn6
				fi
				if [ -n "$qns6" ]; then
					f6="-p tcp -m multiport --dports $HTTPS_PORTS_IPT $first_packet_only"
					filter_apply_ipset_target6 f6
					fw_nfqws_post6 $1 "$f6 $desync" $qns6
					fw_reverse_nfqws_rule6 $1 "$f6" $qns6
				fi
			fi

			get_nfqws_qnums_quic qn qn6
			if [ -n "$qn" ]; then
				f4=
				filter_apply_port_target_quic f4
				f4="$f4 $first_packet_only"
				filter_apply_ipset_target4 f4
				fw_nfqws_post4 $1 "$f4 $desync" $qn
			fi
			if [ -n "$qn6" ]; then
				f6=
				filter_apply_port_target_quic f6
				f6="$f6 $first_packet_only"
				filter_apply_ipset_target6 f6
				fw_nfqws_post6 $1 "$f6 $desync" $qn6
			fi
			;;
		custom)
	    		existf zapret_custom_firewall && zapret_custom_firewall $1
			;;
	esac
}

zapret_do_firewall_ipt()
{
	# $1 - 1 - add, 0 - del

	if [ "$1" = 1 ]; then
		echo Applying iptables
	else
		echo Clearing iptables
	fi

	local mode="${MODE_OVERRIDE:-$MODE}"

	[ "$mode" = "tpws-socks" ] && return 0

	# always create ipsets. ip_exclude ipset is required
	[ "$1" = 1 ] && create_ipset no-update

	zapret_do_firewall_rules_ipt "$@"

	if [ "$1" = 1 ] ; then
		existf flow_offloading_exempt && flow_offloading_exempt
	else
		existf flow_offloading_unexempt && flow_offloading_unexempt
		unprepare_tpws_fw
	fi

	return 0
}
