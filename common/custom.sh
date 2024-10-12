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
				unset -f $FUNC
				. "$script"
				existf $FUNC && $FUNC "$@"
			done
		}
	}
}
