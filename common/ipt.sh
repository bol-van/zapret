std_ports
ipt_connbytes="-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes"
IPSET_EXCLUDE="-m set ! --match-set nozapret"
IPSET_EXCLUDE6="-m set ! --match-set nozapret6"
IPBAN_EXCLUDE="-m set ! --match-set ipban"
IPBAN_EXCLUDE6="-m set ! --match-set ipban6"

ipt()
{
	iptables $FW_EXTRA_PRE -C "$@" $FW_EXTRA_POST >/dev/null 2>/dev/null || iptables $FW_EXTRA_PRE -I "$@" $FW_EXTRA_POST
}
ipta()
{
	iptables $FW_EXTRA_PRE -C "$@" $FW_EXTRA_POST >/dev/null 2>/dev/null || iptables $FW_EXTRA_PRE -A "$@" $FW_EXTRA_POST
}
ipt_del()
{
	iptables $FW_EXTRA_PRE -C "$@" $FW_EXTRA_POST >/dev/null 2>/dev/null && iptables $FW_EXTRA_PRE -D "$@" $FW_EXTRA_POST
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
		echo "Inserting ip$4tables rule for $3 : $2"
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

		rule="$2 $IPSET_EXCLUDE dst $IPBAN_EXCLUDE dst -j DNAT --to $TPWS_LOCALHOST4:$3"
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

		rule="$2 $IPSET_EXCLUDE6 dst $IPBAN_EXCLUDE6 dst"
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

		rule="-m mark ! --mark $DESYNC_MARK/$DESYNC_MARK $2 $IPSET_EXCLUDE dst -j NFQUEUE --queue-num $3 --queue-bypass"
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

		rule="-m mark ! --mark $DESYNC_MARK/$DESYNC_MARK $2 $IPSET_EXCLUDE6 dst -j NFQUEUE --queue-num $3 --queue-bypass"
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


fw_reverse_nfqws_rule4()
{
	fw_nfqws_pre4 $1 "$(reverse_nfqws_rule "$2")" $3
}
fw_reverse_nfqws_rule6()
{
	fw_nfqws_pre6 $1 "$(reverse_nfqws_rule "$2")" $3
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

ipt_first_packets()
{
	# $1 - packet count
	[ -n "$1" -a "$1" != keepalive ] && [ "$1" -ge 1 ] && echo "$ipt_connbytes 1:$1"
}
ipt_do_nfqws_in_out()
{
	# $1 - 1 - add, 0 - del
	# $2 - tcp,udp
	# $3 - ports
	# $4 - PKT_OUT. special value : 'keepalive'
	# $5 - PKT_IN
	local f4 f6 first_packets_only
	[ -n "$3" ] || return
	[ -n "$4" -a "$4" != 0 ] &&
	{
		first_packets_only="$(ipt_first_packets $4)"
		f4="-p $2 -m multiport --dports $3 $first_packets_only"
		f6=$f4
		filter_apply_ipset_target f4 f6
		fw_nfqws_post $1 "$f4" "$f6" $QNUM
	}
	[ -n "$5" -a "$5" != 0 ] &&
	{
		first_packets_only="$(ipt_first_packets $5)"
		f4="-p $2 -m multiport --dports $3  $first_packets_only"
		f6=$f4
		filter_apply_ipset_target f4 f6
		fw_reverse_nfqws_rule $1 "$f4" "$f6" $QNUM
	}
}

zapret_do_firewall_standard_tpws_rules_ipt()
{
	# $1 - 1 - add, 0 - del

	local f4 f6

	[ "$TPWS_ENABLE" = 1 -a -n "$TPWS_PORTS" ] && {
		f4="-p tcp -m multiport --dports $TPWS_PORTS_IPT"
		f6=$f4
		filter_apply_ipset_target f4 f6
		fw_tpws $1 "$f4" "$f6" $TPPORT
	}
}
zapret_do_firewall_standard_nfqws_rules_ipt()
{
	# $1 - 1 - add, 0 - del

	[ "$NFQWS_ENABLE" = 1 ] && {
		ipt_do_nfqws_in_out $1 tcp "$NFQWS_PORTS_TCP_IPT" "$NFQWS_TCP_PKT_OUT" "$NFQWS_TCP_PKT_IN"
		ipt_do_nfqws_in_out $1 tcp "$NFQWS_PORTS_TCP_KEEPALIVE_IPT" keepalive "$NFQWS_TCP_PKT_IN"
		ipt_do_nfqws_in_out $1 udp "$NFQWS_PORTS_UDP_IPT" "$NFQWS_UDP_PKT_OUT" "$NFQWS_UDP_PKT_IN"
		ipt_do_nfqws_in_out $1 udp "$NFQWS_PORTS_UDP_KEEPALIVE_IPT" keepalive "$NFQWS_UDP_PKT_IN"
	}
}
zapret_do_firewall_standard_rules_ipt()
{
	# $1 - 1 - add, 0 - del

	zapret_do_firewall_standard_tpws_rules_ipt $1
	zapret_do_firewall_standard_nfqws_rules_ipt $1
}

zapret_do_firewall_rules_ipt()
{
	# $1 - 1 - add, 0 - del

	zapret_do_firewall_standard_rules_ipt $1
	custom_runner zapret_custom_firewall $1
	zapret_do_icmp_filter $1
}

zapret_do_icmp_filter()
{
	# $1 - 1 - add, 0 - del

	local FW_EXTRA_PRE= FW_EXTRA_POST=

	[ "$FILTER_TTL_EXPIRED_ICMP" = 1 ] && {
		[ "$DISABLE_IPV4" = 1 ] || {
			ipt_add_del $1 POSTROUTING -t mangle -m mark --mark $DESYNC_MARK/$DESYNC_MARK -j CONNMARK --or-mark $DESYNC_MARK
			ipt_add_del $1 INPUT -p icmp -m icmp --icmp-type time-exceeded -m connmark --mark $DESYNC_MARK/$DESYNC_MARK -j DROP
			ipt_add_del $1 FORWARD -p icmp -m icmp --icmp-type time-exceeded -m connmark --mark $DESYNC_MARK/$DESYNC_MARK -j DROP
		}
		[ "$DISABLE_IPV6" = 1 ] || {
			ipt6_add_del $1 POSTROUTING -t mangle -m mark --mark $DESYNC_MARK/$DESYNC_MARK -j CONNMARK --or-mark $DESYNC_MARK
			ipt6_add_del $1 INPUT -p icmpv6 -m icmp6 --icmpv6-type time-exceeded -m connmark --mark $DESYNC_MARK/$DESYNC_MARK -j DROP
			ipt6_add_del $1 FORWARD -p icmpv6 -m icmp6 --icmpv6-type time-exceeded -m connmark --mark $DESYNC_MARK/$DESYNC_MARK -j DROP
		}
	}
}

zapret_do_firewall_ipt()
{
	# $1 - 1 - add, 0 - del

	if [ "$1" = 1 ]; then
		echo Applying iptables
	else
		echo Clearing iptables
	fi

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
