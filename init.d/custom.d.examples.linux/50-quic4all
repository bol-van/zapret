# this custom script runs desync to all IETF QUIC initials
# NOTE: @ih requires nft 1.0.1+ and updated kernel version. it's confirmed to work on 5.15 (openwrt 23) and not work on 5.10 (openwrt 22)

# can override in config :
NFQWS_OPT_DESYNC_QUIC="${NFQWS_OPT_DESYNC_QUIC:---dpi-desync=fake --dpi-desync-repeats=2}"

alloc_dnum DNUM_QUIC4ALL
alloc_qnum QNUM_QUIC4ALL

zapret_custom_daemons()
{
	# $1 - 1 - add, 0 - stop

	local opt="--qnum=$QNUM_QUIC4ALL $NFQWS_OPT_DESYNC_QUIC"
	do_nfqws $1 $DNUM_QUIC4ALL "$opt"
}
zapret_custom_firewall()
{
        # $1 - 1 - run, 0 - stop

	local f='-p udp -m u32 --u32'
	fw_nfqws_post $1 "$f 0>>22&0x3C@4>>16=264:65535&&0>>22&0x3C@8>>28=0xC&&0>>22&0x3C@9=0x00000001" "$f 44>>16=264:65535&&48>>28=0xC&&49=0x00000001" $QNUM_QUIC4ALL
}
zapret_custom_firewall_nft()
{
        # stop logic is not required

	local f="udp length >= 264 @ih,0,4 0xC @ih,8,32 0x00000001"
	nft_fw_nfqws_post "$f" "$f" $QNUM_QUIC4ALL
}
