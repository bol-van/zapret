#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"


TMPLIST="$TMPDIR/list_nethub.txt"
URL4="http://list.nethub.fi/reestr_smart4.txt"
URL6="http://list.nethub.fi/reestr_smart6.txt"


dl()
{
  # $1 - url
  # $2 - file
  curl -vH "Accept-Encoding: gzip" -k --fail --max-time 180 --connect-timeout 10 --retry 4 --max-filesize 33554432 "$1" | gunzip - >"$TMPLIST" ||
  {
   echo list download failed : $1
   exit 2
  }
  dlsize=$(LANG=C wc -c "$TMPLIST" | xargs | cut -f 1 -d ' ')
  if test $dlsize -lt 32768; then
   echo list is too small : $dlsize bytes. can be bad.
   exit 2
  fi
  zz "$2" <"$TMPLIST"
  rm -f "$TMPLIST"
}

getuser && {
 [ "$DISABLE_IPV4" != "1" ] && dl "$URL4" "$ZIPLIST"
 [ "$DISABLE_IPV6" != "1" ] && dl "$URL6" "$ZIPLIST6"
}

"$IPSET_DIR/create_ipset.sh"
