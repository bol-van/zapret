#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"

ZREESTR="$TMPDIR/zapret.txt"
ZDIG="$TMPDIR/zapret-dig.txt"
ZIPLISTTMP="$TMPDIR/zapret-ip.txt"
#ZURL=https://reestr.rublacklist.net/api/current
ZURL=https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv

getuser && {
 # both disabled
 [ "$DISABLE_IPV4" = "1" ] && [ "$DISABLE_IPV6" = "1" ] && exit 0

 curl -H "Accept-Encoding: gzip" -k --fail --max-time 600 --connect-timeout 5 --retry 3 --max-filesize 251658240 "$ZURL_REESTR" | gunzip - >"$ZREESTR" ||
 {
  echo reestr list download failed   
  exit 2
 }

 dlsize=$(LANG=C wc -c "$ZREESTR" | xargs | cut -f 1 -d ' ')
 if test $dlsize -lt 204800; then
  echo list file is too small. can be bad.
  exit 2
 fi

 echo preparing dig list ..
 LANG=C cut -f2 -d ';' "$ZREESTR"  | LANG=C sed -Ee 's/^\*\.(.+)$/\1/' -ne 's/^[a-z0-9A-Z._-]+$/&/p' >"$ZDIG"
 rm -f "$ZREESTR"

 echo digging started. this can take long ...

 [ "$DISABLE_IPV4" != "1" ] && {
  filedigger "$ZDIG" 4 | cut_local >"$ZIPLISTTMP" || {
   rm -f "$ZDIG"
   exit 1
  }
  ip2net4 <"$ZIPLISTTMP" | zz "$ZIPLIST"
  rm -f "$ZIPLISTTMP"
 }
 [ "$DISABLE_IPV6" != "1" ] && {
  filedigger "$ZDIG" 6 | cut_local6 >"$ZIPLISTTMP" || {
   rm -f "$ZDIG"
   exit 1
  }
  ip2net6 <"$ZIPLISTTMP" | zz "$ZIPLIST6"
  rm -f "$ZIPLISTTMP"
 }
 rm -f "$ZDIG"
}

"$IPSET_DIR/create_ipset.sh"
