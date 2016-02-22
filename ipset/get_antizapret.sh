#!/bin/sh
# get ip list from antizapret.prostovpn.org

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/def.sh"

ZURL=http://antizapret.prostovpn.org/proxy.pac
ZIPLISTTMP=/tmp/zapret-ip.txt

$EXEDIR/get_user.sh

curl --fail --max-time 60 --max-filesize 4194304 "$ZURL" | sed -nre "s/\"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\"/\1\n/gp" | sed -nre "s/^[^0-9]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*$/\1/p" >$ZIPLISTTMP &&
{
 dlsize=$(wc -c "$ZIPLISTTMP" | cut -f 1 -d ' ')
 if test $dlsize -lt 20480; then
  echo list file is too small. can be bad.
  exit 2
 fi
 mv -f $ZIPLISTTMP $ZIPLIST
 "$EXEDIR/create_ipset.sh"
}
