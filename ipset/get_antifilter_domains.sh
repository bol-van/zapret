#!/bin/sh

IPSET_DIR="$(dirname "$0")"
IPSET_DIR="$(cd "$IPSET_DIR"; pwd)"

. "$IPSET_DIR/def.sh"

TMPLIST="$TMPDIR/list.txt"

URL="https://antifilter.download/list/domains.lst"

dl()
{
  # $1 - url
  # $2 - file
  # $3 - minsize
  # $4 - maxsize
  curl -L -H "Accept-Encoding: gzip" -k --fail --max-time 60 --connect-timeout 10 --retry 4 --max-filesize 251658240 -o "$TMPLIST" "$1" ||
  {
   echo list download failed : $1
   exit 2
  }
  dlsize=$(LANG=C wc -c "$TMPLIST" | xargs | cut -f 1 -d ' ')
  if test $dlsize -lt $3; then
   echo list is too small : $dlsize bytes. can be bad.
   exit 2
  fi
  zzcat "$TMPLIST" | tr -d '\015' | zz "$2"
  rm -f "$TMPLIST"
}

# useful in case ipban set is used in custom scripts
FAIL=
getipban || FAIL=1
"$IPSET_DIR/create_ipset.sh"
[ -n "$FAIL" ] && exit

dl "$URL" "$ZHOSTLIST" 32768 4194304

exit 0
