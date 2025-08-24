#!/bin/sh

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
BINS=binaries
BINDIR="$EXEDIR/$BINS"

ZAPRET_BASE=${ZAPRET_BASE:-"$EXEDIR"}
. "$ZAPRET_BASE/common/base.sh"

# Function to detect MacOS architecture
detect_macos_arch()
{
	local arch
	case "$(uname -m)" in
		x86_64)
			arch="mac64"
			;;
		arm64)
			arch="mac64-arm64"
			;;
		*)
			arch="mac64"
			;;
	esac
	echo "$arch"
}

read_elf_arch()
{
	# $1 - elf file

	local arch=$(dd if="$1" count=2 bs=1 skip=18 2>/dev/null | hexdump -e '2/1 "%02x"')
	local bit=$(dd if="$1" count=1 bs=1 skip=4 2>/dev/null | hexdump -e '1/1 "%02x"')
	echo $bit$arch
}

select_test_method()
{
	local f ELF

	TEST=run

	# ash and dash try to execute invalid executables as a script. they interpret binary garbage with possible negative consequences
	# bash and zsh do not do this
	if exists bash; then
		TEST=bash
	elif exists zsh && [ "$UNAME" != CYGWIN ] ; then
		TEST=zsh
	elif [ "$UNAME" != Darwin -a "$UNAME" != CYGWIN ]; then
		if exists hexdump and exists dd; then
			# macos does not use ELF
			TEST=elf
			ELF=
			ELF_ARCH=
			for f in /bin/sh /system/bin/sh; do
				[ -x "$f" ] && {
					ELF=$f
					break
				}
			done
			[ -n "$ELF" ] && ELF_ARCH=$(read_elf_arch "$ELF")
			[ -n "$ELF_ARCH" ] && return
		fi

		# find does not use its own shell exec
		# it uses execvp(). in musl libc it does not call shell, in glibc it DOES call /bin/sh
		# that's why prefer bash or zsh if present. otherwise it's our last chance
		if exists find; then
			TEST=find
			FIND=find
		elif exists busybox; then
			busybox find /jGHUa3fh1A 2>/dev/null
			# 127 - command not found
			[ "$?" = 127 ] || {
				TEST=find
				FIND="busybox find"
			}
		fi
	fi

}

disable_antivirus()
{
	# $1 - dir
	[ "$UNAME" = Darwin ] && find "$1" -maxdepth 1 -type f -perm +111 -exec xattr -d com.apple.quarantine {} \; 2>/dev/null
}

check_dir()
{
	local dir="$BINDIR/$1"
	local exe="$dir/ip2net"
	local out
	if [ -f "$exe" ]; then
		if [ -x "$exe" ]; then
			disable_antivirus "$dir"
			case $TEST in
				bash)
					out=$(echo 0.0.0.0 | bash -c "\"$exe"\" 2>/dev/null)
					[ -n "$out" ]
					;;
				zsh)
					out=$(echo 0.0.0.0 | zsh -c "\"$exe\"" 2>/dev/null)
					[ -n "$out" ]
					;;
				elf)
					out=$(read_elf_arch "$exe")
					[ "$ELF_ARCH" = "$out" ] && {
						# exec test to verify it actually works. no illegal instruction or crash.
						out=$(echo 0.0.0.0 | "$exe" 2>/dev/null)
						[ -n "$out" ]
					}
					;;
				find)
					out=$(echo 0.0.0.0 | $FIND "$dir" -maxdepth 1 -name ip2net -exec {} \; 2>/dev/null)
					[ -n "$out" ]
					;;
				run)
					out=$(echo 0.0.0.0 | "$exe" 2>/dev/null)
					[ -n "$out" ]
					;;
				*)
					false
					;;
			esac
		else
			echo >&2 "$exe is not executable. set proper chmod."
			return 1
		fi
	else
		echo >&2 "$exe is absent"
		return 2
	fi
}

# link or copy executables. uncomment either ln or cp, comment other
ccp()
{
	local F="$(basename "$1")"
	[ -d "$ZAPRET_BASE/$2" ] || mkdir "$ZAPRET_BASE/$2"
	[ -f "$ZAPRET_BASE/$2/$F" ] && rm -f "$ZAPRET_BASE/$2/$F"
	ln -fs "../$BINS/$1" "$ZAPRET_BASE/$2" && echo linking : "../$BINS/$1" =\> "$ZAPRET_BASE/$2"
	#cp -f "../$BINS/$1" "$ZAPRET_BASE/$2" && echo copying : "../$BINS/$1" =\> "$ZAPRET_BASE/$2"
}


UNAME=$(uname)

[ "$1" = getarch ] ||
if [ ! -d "$BINDIR" ] || ! dir_is_not_empty "$BINDIR" ]; then
	echo "no binaries found"
	case $UNAME in
		Linux)
			echo "you need to download release from github or build binaries from source"
			echo "building from source requires debian/ubuntu packages : make gcc zlib1g-dev libcap-dev libnetfilter-queue-dev libmnl-dev libsystemd-dev"
			echo "libsystemd-dev required only on systemd based systems"
			echo "on distributions with other package manager find dev package analogs"
			echo "to compile on systems with systemd : make systemd"
			echo "to compile on other systems : make"
			;;
		Darwin)
			echo "you need to download release from github or build binaries from source"
			echo "to compile for current architecture : make mac"
			echo "to compile universal binary (x86_64 + arm64) : make mac-universal"
			;;
		FreeBSD)
			echo "you need to download release from github or build binaries from source"
			echo "to compile : make"
			;;
		OpenBSD)
			echo "to compile : make bsd"
			;;
		CYGWIN*)
			echo "you need to download release from github or build binaries from source"
			echo "to compile : read docs"
			echo "to make things easier use zapret-win-bundle"
			;;
	esac
	exit 1
fi

unset PKTWS
case $UNAME in
	Linux)
		ARCHLIST="my linux-x86_64 linux-x86 linux-arm64 linux-arm linux-mips64 linux-mipsel linux-mips linux-lexra linux-ppc"
		PKTWS=nfqws
		;;
	Darwin)
		ARCHLIST="my mac64 mac64-arm64"
		;;
	FreeBSD)
		ARCHLIST="my freebsd-x86_64"
		PKTWS=dvtws
		;;
	CYGWIN*)
		UNAME=CYGWIN
		ARCHLIST="windows-x86_64 windows-x86"
		PKTWS=winws
		;;
	*)
		ARCHLIST="my"
esac

select_test_method

if [ "$1" = "getarch" ]; then
	# For MacOS, try to detect architecture and prioritize matching binaries
	if [ "$UNAME" = "Darwin" ]; then
		local detected_arch=$(detect_macos_arch)
		echo "detected MacOS architecture: $detected_arch"
		
		# First try the detected architecture
		if [ -d "$BINDIR/$detected_arch" ] && check_dir "$detected_arch"; then
			echo "$detected_arch"
			exit 0
		fi
		
		# Then try universal binary
		if [ -d "$BINDIR/mac64" ] && check_dir "mac64"; then
			echo "mac64"
			exit 0
		fi
		
		# Finally try the other architecture
		if [ "$detected_arch" = "mac64" ] && [ -d "$BINDIR/mac64-arm64" ] && check_dir "mac64-arm64"; then
			echo "mac64-arm64"
			exit 0
		elif [ "$detected_arch" = "mac64-arm64" ] && [ -d "$BINDIR/mac64" ] && check_dir "mac64"; then
			echo "mac64"
			exit 0
		fi
	else
		# For other systems, use the original logic
		for arch in $ARCHLIST
		do
			[ -d "$BINDIR/$arch" ] || continue
			if check_dir $arch; then
				echo $arch
				exit 0
			fi
		done
	fi
else
	echo "using arch detect method : $TEST${ELF_ARCH:+ $ELF_ARCH}"

	for arch in $ARCHLIST
	do
		[ -d "$BINDIR/$arch" ] || continue
		if check_dir $arch; then
			echo $arch is OK
			echo installing binaries ...
			ccp $arch/ip2net ip2net
			ccp $arch/mdig mdig
			[ -n "$PKTWS" ] && ccp $arch/$PKTWS nfq
			[ "$UNAME" = CYGWIN ] || ccp $arch/tpws tpws
			exit 0
		else
			echo $arch is NOT OK
		fi
	done
	echo no compatible binaries found
fi

exit 1
