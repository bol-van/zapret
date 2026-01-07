#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"

ZREESTR="$TMPDIR/zapret.txt.gz"
IPB="$TMPDIR/ipb.txt"
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
 LC_ALL=C LANG=C gunzip -c "$ZREESTR" | cut -s -f2 -d';' | LC_ALL=C  LANG=C nice -n 5 sed -Ee 's/^\*\.(.+)$/\1/' -ne 's/^[a-z0-9A-Z._-]+$/&/p' | $AWK '{ print tolower($0) }'
}
reestr_extract_ip()
{
 LC_ALL=C LANG=C gunzip -c | nice -n 5 $AWK -F ';' '($1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}/) && (($2 == "" && $3 == "") || ($1 == $2)) {gsub(/ \| /, RS); print $1}' | LC_ALL=C  LANG=C $AWK '{split($1, a, /\|/); for (i in a) {print a[i]}}'
}

ipban_fin()
{
 getipban
 "$IPSET_DIR/create_ipset.sh"
}

dl_checked "$ZURL_REESTR" "$ZREESTR" 204800 251658240 600 || {
 ipban_fin
 exit 2
}

reestr_list | sort -u | zz "$ZHOSTLIST"

reestr_extract_ip <"$ZREESTR" >"$IPB"

rm -f "$ZREESTR"
[ "$DISABLE_IPV4" != "1" ] && $AWK '/^([0-9]{1,3}\.){3}[0-9]{1,3}($|(\/[0-9]{2}$))/' "$IPB" | cut_local | ip2net4 | zz "$ZIPLIST_IPBAN"
[ "$DISABLE_IPV6" != "1" ] && $AWK '/^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}($|(\/[0-9]{2,3}$))/' "$IPB" | cut_local6 | ip2net6 | zz "$ZIPLIST_IPBAN6"
rm -f "$IPB"

hup_zapret_daemons

ipban_fin

exit 0
