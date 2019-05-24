#!/bin/sh
# get ip list from antizapret.prostovpn.org

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/def.sh"

#ZURL=https://github.com/zapret-info/z-i/raw/master/dump.csv
ZURL=http://antizapret.prostovpn.org/iplist.txt
ZIPLISTTMP="$TMPDIR/zapret-ip.txt"

getuser

curl --fail --max-time 150 --connect-timeout 5 --max-filesize 20971520 -k -L "$ZURL" | cut_local >"$ZIPLISTTMP" &&
{
 dlsize=$(wc -c "$ZIPLISTTMP" | cut -f 1 -d ' ')
 if test $dlsize -lt 204800; then
  echo list file is too small. can be bad.
  exit 2
 fi
 cat "$ZIPLISTTMP" | zz "$ZIPLIST"
 rm -f "$ZIPLISTTMP" "$ZIPLIST"
 "$EXEDIR/create_ipset.sh"
}
