#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"

ZREESTR="$TMPDIR/reestr.txt"
#ZURL_REESTR=https://reestr.rublacklist.net/api/current
ZURL_REESTR=https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv


awkgrep()
{ 
 # $1 - pattern
 LANG=C nice -n 5 $AWK "{while ( match(\$0,/$1[ |;]/) ) { print substr(\$0,RSTART,RLENGTH-1); \$0=substr(\$0,RSTART+RLENGTH) } }"
}

dig_reestr()
{
 # $1 - grep ipmask
 # $2 - iplist
 # $3 - ip version : 4,6

 echo processing reestr list $2

 tail -n +2 "$ZREESTR" | awkgrep "$1" | cut_local | ip2net$3 | zz "$2"
}

getuser && {
 curl -H "Accept-Encoding: gzip" -k --fail --max-time 600 --connect-timeout 5 --retry 3 --max-filesize 251658240 "$ZURL_REESTR" | gunzip - >"$ZREESTR" ||
 {
  echo reestr list download failed
  exit 2
 }
 dlsize=$(LANG=C wc -c "$ZREESTR" | xargs | cut -f 1 -d ' ')
 if test $dlsize -lt 1048576; then
  echo reestr ip list is too small. can be bad.
  exit 2
 fi
 #sed -i 's/\\n/\r\n/g' $ZREESTR

 get_ip_regex

 [ "$DISABLE_IPV4" != "1" ] && {
  dig_reestr "$REG_IPV4" "$ZIPLIST" 4
 }

 [ "$DISABLE_IPV6" != "1" ] && {
  dig_reestr "$REG_IPV6" "$ZIPLIST6" 6
 }

 rm -f "$ZREESTR"
}

"$IPSET_DIR/create_ipset.sh"
