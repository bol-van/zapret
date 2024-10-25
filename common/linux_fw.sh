set_conntrack_liberal_mode()
{
	[ -n "$SKIP_CONNTRACK_LIBERAL_MODE" ] || sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=$1
}
zapret_do_firewall()
{
	linux_fwtype

	[ "$1" = 1 -a -n "$INIT_FW_PRE_UP_HOOK" ] && $INIT_FW_PRE_UP_HOOK
	[ "$1" = 0 -a -n "$INIT_FW_PRE_DOWN_HOOK" ] && $INIT_FW_PRE_DOWN_HOOK

	case "$FWTYPE" in
		iptables)
			zapret_do_firewall_ipt "$@"
			;;
		nftables)
			zapret_do_firewall_nft "$@"
			;;
	esac

	# russian DPI sends RST,ACK with wrong ACK.
	# this is sometimes treated by conntrack as invalid and connbytes fw rules do not pass RST packet to nfqws.
	# switch on liberal mode on zapret firewall start and switch off on zapret firewall stop
	# this is only required for processing incoming bad RSTs. incoming rules are only applied in autohostlist mode
	# calling this after firewall because conntrack module can be not loaded before applying conntrack firewall rules
	[ "$MODE_FILTER" = "autohostlist" ] && set_conntrack_liberal_mode $1
	
	[ "$1" = 1 -a -n "$INIT_FW_POST_UP_HOOK" ] && $INIT_FW_POST_UP_HOOK
	[ "$1" = 0 -a -n "$INIT_FW_POST_DOWN_HOOK" ] && $INIT_FW_POST_DOWN_HOOK

	return 0
}
zapret_apply_firewall()
{
	zapret_do_firewall 1 "$@"
}
zapret_unapply_firewall()
{
	zapret_do_firewall 0 "$@"
}
