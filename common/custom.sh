custom_runner()
{
	# $1 - function name
	# $2+ - params

	[ "$DISABLE_CUSTOM" = 1 ] && return 0

	local n script FUNC=$1

	shift

	[ -d "$CUSTOM_DIR/custom.d" ] && {
		dir_is_not_empty "$CUSTOM_DIR/custom.d" && {
			for script in "$CUSTOM_DIR/custom.d/"*; do
				[ -f "$script" ] || continue
				DAEMON_CFGNAME_SAVED="$DAEMON_CFGNAME"
				unset DAEMON_CFGNAME
				unset -f $FUNC
				. "$script"
				if [ -z "$DAEMON_CFGNAME" ]; then
					DAEMON_CFGNAME="$(basename "$script")"
					DAEMON_CFGNAME="${DAEMON_CFGNAME%%.*}"
				fi
				existf $FUNC && $FUNC "$@"
				DAEMON_CFGNAME="$DAEMON_CFGNAME_SAVED"
			done
		}
	}
}

alloc_tpws_port()
{
	# $1 - target var name
	alloc_num NUMPOOL_TPWS_PORT $1 910 979
}
alloc_qnum()
{
	# $1 - target var name
	alloc_num NUMPOOL_QNUM $1 65400 65499
}
alloc_dnum()
{
	# alloc daemon number
	# $1 - target var name
	alloc_num NUMPOOL_DNUM $1 1000 1999
}
