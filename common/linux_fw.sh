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
