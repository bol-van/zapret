zapret_do_firewall()
{
	linux_fwtype

	case "$FWTYPE" in
		iptables)
			zapret_do_firewall_ipt "$@"
			;;
		nftables)
			zapret_do_firewall_nft "$@"
			;;
	esac

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
