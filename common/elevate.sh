require_root()
{
	local exe preserve_env
	echo \* checking privileges
	[ $(id -u) -ne "0" ] && {
		echo root is required
		exe="$EXEDIR/$(basename "$0")"
		exists sudo && {
			echo elevating with sudo
			exec sudo -E sh "$exe"
		}
		exists su && {
			echo elevating with su
			case "$UNAME" in
				Linux)
					preserve_env="--preserve-environment"
					;;
				FreeBSD|OpenBSD|Darwin)
					preserve_env="-m"
					;;
			esac
			exec su $preserve_env root -c "sh \"$exe\""
		}
		echo su or sudo not found
		exitp 2
	}
	HAVE_ROOT=1
}
