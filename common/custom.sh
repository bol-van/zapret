custom_runner()
{
	# $1 - function name
	# $2+ - params

	local n script FUNC=$1

	shift

	[ -f "$CUSTOM_DIR/custom" ] && {
		unset -f $FUNC
		. "$CUSTOM_DIR/custom"
		existf $FUNC && $FUNC "$@"
	}
	[ -d "$CUSTOM_DIR/custom.d" ] && {
		n=$(ls "$CUSTOM_DIR/custom.d" | wc -c | xargs)
		[ "$n" = 0 ] || {
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
