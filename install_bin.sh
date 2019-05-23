#!/bin/sh

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")
BINS=binaries
BINDIR=$EXEDIR/$BINS

check_dir()
{
	echo 0.0.0.0 | "$BINDIR/$1/ip2net" 1>/dev/null 2>/dev/null
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

ARCHLIST="my x86_64 x86 aarch64 armhf mips64r2-msb mips32r1-lsb mips32r1-msb ppc"

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
			ccp $arch/nfqws nfq
			ccp $arch/tpws tpws
	 		exit 0
		else
			echo $arch is NOT OK
		fi
	done
fi

exit 1
