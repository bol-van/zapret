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
		f="-m multiport --dports 80,443"
	elif [ "$MODE_HTTPS" = "1" ]; then
		f="--dport 443"
	elif [ "$MODE_HTTP" = "1" ]; then
		f="--dport 80"
	else
		echo WARNING !!! HTTP and HTTPS are both disabled
	fi
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

	local first_packet_only="-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:4"
	local desync="-m mark ! --mark $DESYNC_MARK/$DESYNC_MARK"
	local f4 f6 qn qns qn6 qns6

	# always create ipsets. ip_exclude ipset is required
	[ "$1" = 1 ] && create_ipset no-update

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
			else
				if [ -n "$qn" ]; then
					f4="--dport 80"
					[ "$MODE_HTTP_KEEPALIVE" = "1" ] || f4="$f4 $first_packet_only"
					filter_apply_ipset_target4 f4
					fw_nfqws_post4 $1 "$f4 $desync" $qn
				fi
				if [ -n "$qns" ]; then
					f4="--dport 443 $first_packet_only"
					filter_apply_ipset_target4 f4
					fw_nfqws_post4 $1 "$f4 $desync" $qns
				fi
			fi
			if [ "$MODE_HTTP_KEEPALIVE" != "1" ] && [ -n "$qn6" ] && [ "$qn6" = "$qns6" ]; then
				filter_apply_port_target f6
				f6="$f6 $first_packet_only"
				filter_apply_ipset_target6 f6
				fw_nfqws_post6 $1 "$f6 $desync" $qn6
			else
				if [ -n "$qn6" ]; then
					f6="--dport 80"
					[ "$MODE_HTTP_KEEPALIVE" = "1" ] || f6="$f6 $first_packet_only"
					filter_apply_ipset_target6 f6
					fw_nfqws_post6 $1 "$f6 $desync" $qn6
				fi
				if [ -n "$qns6" ]; then
					f6="--dport 443 $first_packet_only"
					filter_apply_ipset_target6 f6
					fw_nfqws_post6 $1 "$f6 $desync" $qns6
				fi
			fi
			;;
		custom)
	    		existf zapret_custom_firewall && zapret_custom_firewall $1
			;;
	esac

	if [ "$1" = 1 ] ; then
		existf flow_offloading_exempt && flow_offloading_exempt
	else
		existf flow_offloading_unexempt && flow_offloading_unexempt
		unprepare_tpws_fw
	fi

	return 0
}
