require_root()
{
	local exe
	echo \* checking privileges
	[ $(id -u) -ne "0" ] && {
		echo root is required
		exe="$EXEDIR/$(basename "$0")"
		exists sudo && exec sudo sh "$exe"
		exists su && exec su root -c "sh \"$exe\""
		echo su or sudo not found
		exitp 2
	}
}
