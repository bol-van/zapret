#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"

TMPLIST="$TMPDIR/list.txt"

BASEURL="https://raw.githubusercontent.com/bol-van/rulist/main"
URL4="$BASEURL/reestr_smart4.txt"
URL6="$BASEURL/reestr_smart6.txt"
IPB4="$BASEURL/reestr_ipban4.txt"
IPB6="$BASEURL/reestr_ipban6.txt"

dl()
{
  # $1 - url
  # $2 - file
  # $3 - minsize
  # $4 - maxsize
  curl -H "Accept-Encoding: gzip" -k --fail --max-time 120 --connect-timeout 10 --retry 4 --max-filesize $4 -o "$TMPLIST" "$1" ||
  {
   echo list download failed : $1
   exit 2
  }
  dlsize=$(LC_ALL=C LANG=C wc -c "$TMPLIST" | xargs | cut -f 1 -d ' ')
  if test $dlsize -lt $3; then
   echo list is too small : $dlsize bytes. can be bad.
   exit 2
  fi
  zzcopy "$TMPLIST" "$2"
  rm -f "$TMPLIST"
}

getuser && {
 [ "$DISABLE_IPV4" != "1" ] && {
 	dl "$URL4" "$ZIPLIST" 32768 4194304
 	dl "$IPB4" "$ZIPLIST_IPBAN" 8192 1048576
 }
 [ "$DISABLE_IPV6" != "1" ] && {
 	dl "$URL6" "$ZIPLIST6" 8192 4194304
 	dl "$IPB6" "$ZIPLIST_IPBAN6" 128 1048576
 }
}

"$IPSET_DIR/create_ipset.sh"
