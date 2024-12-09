standard_mode_tpws_socks()
{
	# $1 - 1 - run, 0 - stop
	local opt
	[ "$TPWS_SOCKS_ENABLE" = 1 ] && {
		opt="--port=$TPPORT_SOCKS $TPWS_SOCKS_OPT"
		filter_apply_hostlist_target opt
		do_tpws_socks $1 2 "$opt"
	}
}
standard_mode_tpws()
{
	# $1 - 1 - run, 0 - stop
	local opt
	[ "$TPWS_ENABLE" = 1 ] && check_bad_ws_options $1 "$TPWS_OPT" && {
		opt="--port=$TPPORT $TPWS_OPT"
		filter_apply_hostlist_target opt
		do_tpws $1 1 "$opt"
	}
}
standard_mode_nfqws()
{
	# $1 - 1 - run, 0 - stop
	local opt
	[ "$NFQWS_ENABLE" = 1 ] && check_bad_ws_options $1 "$NFQWS_OPT" && {
		opt="--qnum=$QNUM $NFQWS_OPT"
		filter_apply_hostlist_target opt
		do_nfqws $1 3 "$opt"
	}
}
standard_mode_daemons()
{
	# $1 - 1 - run, 0 - stop

	standard_mode_tpws_socks $1
	standard_mode_tpws $1
	standard_mode_nfqws $1
}
zapret_do_daemons()
{
	# $1 - 1 - run, 0 - stop

	standard_mode_daemons $1
	custom_runner zapret_custom_daemons $1

	return 0
}
zapret_run_daemons()
{
	zapret_do_daemons 1 "$@"
}
zapret_stop_daemons()
{
	zapret_do_daemons 0 "$@"
}
