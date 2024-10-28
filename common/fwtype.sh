linux_ipt_avail()
{
	exists iptables && exists ip6tables
}
linux_maybe_iptables_fwtype()
{
	linux_ipt_avail && FWTYPE=iptables
}
linux_nft_avail()
{
	exists nft
}
linux_fwtype()
{
	[ -n "$FWTYPE" ] && return

	FWTYPE=unsupported

	linux_get_subsys
	if [ "$SUBSYS" = openwrt ] ; then
		# linux kernel is new enough if fw4 is there
		if [ -x /sbin/fw4 ] && linux_nft_avail ; then
			FWTYPE=nftables
		else
			linux_maybe_iptables_fwtype
		fi
	else
		SUBSYS=
		# generic linux
		# flowtable is implemented since kernel 4.16
		if linux_nft_avail && linux_min_version 4 16; then
			FWTYPE=nftables
		else
			linux_maybe_iptables_fwtype
		fi
	fi

	export FWTYPE
}

get_fwtype()
{
	[ -n "$FWTYPE" ] && return

	local UNAME="$(uname)"

	case "$UNAME" in
		Linux)
			linux_fwtype
			;;
		FreeBSD)
			if exists ipfw ; then
				FWTYPE=ipfw
			else
				FWTYPE=unsupported
			fi
			;;
		*)
			FWTYPE=unsupported
			;;
	esac

	export FWTYPE
}
