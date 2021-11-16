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
 # $3 - ipban list
 # $4 - ip version : 4,6

 local DOMMASK='^.*;[^ ;:/]+\.[^ ;:/]+;'
 local TMP="$TMPDIR/tmp.txt"

 echo processing reestr lists $2 $3

 # find entries with https or without domain name - they should be banned by IP
 # 2971-18 is TELEGRAM. lots of proxy IPs banned, list grows very large
 (nice -n 5 $GREP -avE "$DOMMASK" "$ZREESTR" ; $GREP -a "https://" "$ZREESTR") |
  awkgrep "$1" | cut_local | sort -u >$TMP

 ip2net$4 <"$TMP" | zz "$3" 

 # other IPs go to regular zapret list
 tail -n +2 "$ZREESTR"  | awkgrep "$1" | cut_local | nice -n 5 $GREP -xvFf "$TMP" | ip2net$4 | zz "$2"

 rm -f "$TMP"
}

getuser && {

 curl -k --fail --max-time 600 --connect-timeout 5 --retry 3 --max-filesize 251658240 "$ZURL_REESTR" -o "$ZREESTR" ||
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
  dig_reestr "$REG_IPV4" "$ZIPLIST" "$ZIPLIST_IPBAN" 4
 }

 [ "$DISABLE_IPV6" != "1" ] && {
  dig_reestr "$REG_IPV6" "$ZIPLIST6" "$ZIPLIST_IPBAN6" 6
 }

 rm -f "$ZREESTR"
}

"$IPSET_DIR/create_ipset.sh"
