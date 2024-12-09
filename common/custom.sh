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
				unset -f $FUNC
				. "$script"
				existf $FUNC && $FUNC "$@"
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
