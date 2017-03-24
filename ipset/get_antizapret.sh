#!/bin/sh
# get ip list from antizapret.prostovpn.org

SCRIPT=$(readlink -f $0)
EXEDIR=$(dirname $SCRIPT)

. "$EXEDIR/def.sh"

#ZURL=https://github.com/zapret-info/z-i/raw/master/dump.csv
ZURL=http://antizapret.prostovpn.org/iplist.txt
ZIPLISTTMP=/tmp/zapret-ip.txt

getuser

#curl --fail --max-time 300 --max-filesize 33554432 -k -L "$ZURL" \
#    | sed -nre "s/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/\1\n/gp" \
#    | sed -nre "s/^[^0-9]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*$/\1/p" \
#    | grep -vE '^192\.168\.[0-9]+\.[0-9]+$' | grep -vE '^127\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -vE '^10\.[0-9]+\.[0-9]+\.[0-9]+$' \
#    | sort -u \
curl --fail --max-time 300 --max-filesize 33554432 -k -L "$ZURL" \
    | grep -vE '^192\.168\.[0-9]+\.[0-9]+$' | grep -vE '^127\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -vE '^10\.[0-9]+\.[0-9]+\.[0-9]+$' \
    >$ZIPLISTTMP &&
{
 dlsize=$(wc -c "$ZIPLISTTMP" | cut -f 1 -d ' ')
 if test $dlsize -lt 204800; then
  echo list file is too small. can be bad.
  exit 2
 fi
 mv -f $ZIPLISTTMP $ZIPLIST
 "$EXEDIR/create_ipset.sh"
}
