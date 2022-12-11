#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"


TMPLIST="$TMPDIR/list_nethub.txt"
URL4="http://list.nethub.fi/reestr_resolved4.txt"
URL6="http://list.nethub.fi/reestr_resolved6.txt"


getuser && {
 [ "$DISABLE_IPV4" != "1" ] && {
  curl -vH "Accept-Encoding: gzip" -k --fail --max-time 180 --connect-timeout 10 --retry 4 --max-filesize 33554432 "$URL4" | gunzip - >"$TMPLIST" ||
  {
   echo ipv4 list download failed
   exit 2
  }
  dlsize=$(LANG=C wc -c "$TMPLIST" | xargs | cut -f 1 -d ' ')
  if test $dlsize -lt 32768; then
   echo list is too small. can be bad.
   exit 2
  fi
  zz "$ZIPLIST" <"$TMPLIST"
  rm -f "$TMPLIST"
 }
 [ "$DISABLE_IPV6" != "1" ] && {
  curl -H "Accept-Encoding: gzip" -k --fail --max-time 180 --connect-timeout 10 --retry 4 --max-filesize 33554432 "$URL6" | gunzip - >"$TMPLIST" ||
  {
   echo ipv4 list download failed
   exit 2
  }
  dlsize=$(LANG=C wc -c "$TMPLIST" | xargs | cut -f 1 -d ' ')
  if test $dlsize -lt 32768; then
   echo list is too small. can be bad.
   exit 2
  fi
  zz "$ZIPLIST6" <"$TMPLIST"
  rm -f "$TMPLIST"
 }
}

"$IPSET_DIR/create_ipset.sh"
