#!/bin/sh

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"
BINS=binaries
BINDIR="$EXEDIR/$BINS"

check_dir()
{
	local exe=$BINDIR/$1/ip2net
	if [ -f "$exe" ]; then
		if [ -x "$exe" ]; then
			echo 0.0.0.0 | "$exe" 1>/dev/null 2>/dev/null
		else
			echo "$exe is not executable. set proper chmod."
			return 1
		fi
	else
		echo "$exe is absent"
		return 2
	fi
}

# link or copy executables. uncomment either ln or cp, comment other
ccp()
{
	local F=$(basename $1)
	[ -d "$EXEDIR/$2" ] || mkdir "$EXEDIR/$2"
	[ -f "$EXEDIR/$2/$F" ] && rm -f "$EXEDIR/$2/$F"
	ln -fs "../$BINS/$1" "$EXEDIR/$2" && echo linking : "../$BINS/$1" =\> "$EXEDIR/$2"
	#cp -f "$BINDIR/$1" "$EXEDIR/$2" && echo copying : "$BINDIR/$1" =\> "$EXEDIR/$2"
}

UNAME=$(uname)
if [ "$UNAME" = "Linux" ]; then
 ARCHLIST="my x86_64 x86 aarch64 arm mips64r2-msb mips32r1-lsb mips32r1-msb ppc"
elif [ "$UNAME" = "Darwin" ]; then
 ARCHLIST="my mac64"
else
 ARCHLIST="my"
fi

if [ "$1" = "getarch" ]; then
	for arch in $ARCHLIST
	do
		[ -d "$BINDIR/$arch" ] || continue
		if check_dir $arch; then
	 		echo $arch
	 		exit 0
	 	fi
	done
else
	for arch in $ARCHLIST
	do
		[ -d "$BINDIR/$arch" ] || continue
		if check_dir $arch; then
			echo $arch is OK
			echo installing binaries ...
			ccp $arch/ip2net ip2net
			ccp $arch/mdig mdig
			if [ "$(uname)" = "Linux" ]; then
			 ccp $arch/nfqws nfq
			else
			 ccp $arch/dvtws nfq
			fi
			ccp $arch/tpws tpws
	 		exit 0
		else
			echo $arch is NOT OK
		fi
	done
	echo no compatible binaries found
fi

exit 1
