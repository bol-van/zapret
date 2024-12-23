#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"

ZREESTR="$TMPDIR/zapret.txt.gz"
ZDIG="$TMPDIR/zapret-dig.txt"
IPB="$TMPDIR/ipb.txt"
ZIPLISTTMP="$TMPDIR/zapret-ip.txt"
#ZURL=https://reestr.rublacklist.net/api/current
ZURL_REESTR=https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv.gz

dl_checked()
{
  # $1 - url
  # $2 - file
  # $3 - minsize
  # $4 - maxsize
  # $5 - maxtime
  curl -k --fail --max-time $5 --connect-timeout 10 --retry 4 --max-filesize $4 -o "$2" "$1" ||
  {
   echo list download failed : $1
   return 2
  }
  dlsize=$(LC_ALL=C LANG=C wc -c "$2" | xargs | cut -f 1 -d ' ')
  if test $dlsize -lt $3; then
   echo list is too small : $dlsize bytes. can be bad.
   return 2
  fi
  return 0
}

reestr_list()
{
 LC_ALL=C LANG=C gunzip -c "$ZREESTR" | cut -s -f2 -d';' | LC_ALL=C LANG=C nice -n 5 sed -Ee 's/^\*\.(.+)$/\1/' -ne 's/^[a-z0-9A-Z._-]+$/&/p' | $AWK '{ print tolower($0) }'
}
reestr_extract_ip()
{
 LC_ALL=C LANG=C gunzip -c | nice -n 5 $AWK -F ';' '($1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}/) && (($2 == "" && $3 == "") || ($1 == $2)) {gsub(/ \| /, RS); print $1}' | LC_ALL=C LANG=C $AWK '{split($1, a, /\|/); for (i in a) {print a[i]}}'
}

getuser && {
 # both disabled
 [ "$DISABLE_IPV4" = "1" ] && [ "$DISABLE_IPV6" = "1" ] && exit 0

 dl_checked "$ZURL_REESTR" "$ZREESTR" 204800 251658240 600 || exit 2
 
 echo preparing ipban list ..
 
 reestr_extract_ip <"$ZREESTR" >"$IPB"
 [ "$DISABLE_IPV4" != "1" ] && $AWK '/^([0-9]{1,3}\.){3}[0-9]{1,3}($|(\/[0-9]{2}$))/' "$IPB" | cut_local | ip2net4 | zz "$ZIPLIST_IPBAN"
 [ "$DISABLE_IPV6" != "1" ] && $AWK '/^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}($|(\/[0-9]{2,3}$))/' "$IPB" | cut_local6 | ip2net6 | zz "$ZIPLIST_IPBAN6"
 rm -f "$IPB"

 echo preparing dig list ..
 reestr_list | sort -u >"$ZDIG"

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
