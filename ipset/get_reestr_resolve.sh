#!/bin/sh

SCRIPT=$(readlink -f "$0")
EXEDIR=$(dirname "$SCRIPT")

. "$EXEDIR/def.sh"

ZREESTR="$TMPDIR/zapret.txt"
ZDIG="$TMPDIR/zapret-dig.txt"
ZIPLISTTMP="$TMPDIR/zapret-ip.txt"
#ZURL=https://reestr.rublacklist.net/api/current
ZURL=https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv

getuser

# both disabled
[ "$DISABLE_IPV4" = "1" ] && [ "$DISABLE_IPV6" = "1" ] && exit 0

curl -k --fail --max-time 150 --connect-timeout 5 --retry 3 --max-filesize 251658240 "$ZURL" >"$ZREESTR" ||
{
 echo reestr list download failed   
 exit 2
}
dlsize=$(wc -c "$ZREESTR" | cut -f 1 -d ' ')
if test $dlsize -lt 204800; then
 echo list file is too small. can be bad.
 exit 2
fi
echo preparing dig list ..
#sed -i 's/\\n/\r\n/g' $ZREESTR
#sed -nre 's/^[^;]*;([^;|\\]{4,250})\;.*$/\1/p' $ZREESTR | sort | uniq >$ZDIG
cut -f2 -d ';' "$ZREESTR"  | grep -avE '^$|\*|:' >"$ZDIG"
rm -f "$ZREESTR"

echo digging started. this can take long ...

[ "$DISABLE_IPV4" != "1" ] && {
 digger "$ZDIG" 4 | cut_local >"$ZIPLISTTMP" || {
  rm -f "$ZDIG"
  exit 1
 }
 sort -u "$ZIPLISTTMP" | zz "$ZIPLIST"
 rm -f "$ZIPLISTTMP"
}
[ "$DISABLE_IPV6" != "1" ] && {
 digger "$ZDIG" 6 | cut_local6 >"$ZIPLISTTMP" || {
  rm -f "$ZDIG"
  exit 1
 }
 sort -u "$ZIPLISTTMP" | zz "$ZIPLIST6"
 rm -f "$ZIPLISTTMP"
}
rm -f "$ZDIG"
"$EXEDIR/create_ipset.sh"
