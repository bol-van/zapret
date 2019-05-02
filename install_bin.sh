#!/bin/sh

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)
BINDIR=$EXEDIR/binaries

check_dir()
{
 echo 0.0.0.0 | $BINDIR/$1/ip2net 1>/dev/null 2>/dev/null
}
ccp()
{
 cp -f $1 $2 && echo "$1" =\> "$2"
}

for arch in aarch64 armhf mips32r1-lsb mips32r1-msb x86_64 x86
do
 if check_dir $arch; then
  echo $arch is OK
  echo copying binaries ...
  ccp $BINDIR/$arch/ip2net $EXEDIR/ip2net
  ccp $BINDIR/$arch/mdig $EXEDIR/mdig
  ccp $BINDIR/$arch/nfqws $EXEDIR/nfq
  ccp $BINDIR/$arch/tpws $EXEDIR/tpws
  break
 else
  echo $arch is NOT OK
 fi
done

