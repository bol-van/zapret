#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"


TMPLIST="$TMPDIR/list_nethub.txt"

# free domain was discontinued
HOST=list.nethub.fi
IP=69.197.166.36
RESOLVE="--resolve $HOST:80:$IP"
URL4="http://list.nethub.fi/reestr_resolved4.txt"
URL6="http://list.nethub.fi/reestr_resolved6.txt"


dl()
{
  # $1 - url
  # $2 - file
  curl -H "Accept-Encoding: gzip" $RESOLVE -k --fail --max-time 180 --connect-timeout 10 --retry 4 --max-filesize 33554432 "$1" | gunzip - >"$TMPLIST" ||
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
